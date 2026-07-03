#include "npu_filter.hpp"
#include "logger.hpp"
#include "payload_normalizer.hpp"
#include "tls_inspector.hpp"
#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <functional>

// True if a network-byte-order IPv4 address is a public (routable) address.
// "Data Exfiltration" implies data leaving the org, so the exfil content tags
// only apply when the destination is external — an internal->internal transfer
// is at most a "Suspicious Transfer", not exfiltration.
static inline bool dst_is_external(uint32_t ip_net_order) {
  const uint8_t *b = reinterpret_cast<const uint8_t *>(&ip_net_order);
  const bool priv = b[0] == 10 || b[0] == 127 || b[0] == 0 ||
                    (b[0] == 172 && (b[1] & 0xF0) == 16) ||
                    (b[0] == 192 && b[1] == 168) ||
                    (b[0] == 169 && b[1] == 254);
  return !priv;
}

NpuFilter::NpuFilter(const WirewolfConfig &config,
                     ThreadSafeQueue<FlowPtr> &in_queue,
                     ThreadSafeQueue<FlowPtr> &out_queue)
    : input_queue(in_queue), output_queue(out_queue),
      cfg(config) {

#ifdef WIREWOLF_USE_OPENVINO
  if (cfg.openvino_enabled) {
    try {
      auto model = core.read_model(cfg.openvino_model_path);

      // Smart device selection: try NPU first, then CPU fallback
      auto devices = core.get_available_devices();
      std::string device = "CPU"; // safe default
      for (const auto &d : devices) {
        if (d == "NPU") {
          device = "NPU";
          break;
        }
      }

      LOG_INFO("filter", "Compiling OpenVINO model on device: " + device);
      compiled_model = core.compile_model(model, device);
      infer_request = compiled_model.create_infer_request();
      openvino_available = true;
      openvino_device = device;
      LOG_INFO("filter", "OpenVINO model loaded from " +
                             cfg.openvino_model_path + " (device=" + device +
                             ")");
    } catch (const std::exception &e) {
      LOG_WARN("filter",
               std::string("OpenVINO init failed, using statistical filter: ") +
                   e.what());
    }
  } else {
    LOG_INFO("filter", "Using statistical anomaly filter");
  }
#else
  LOG_INFO("filter",
           "Using statistical anomaly filter (OpenVINO not compiled)");
#endif

  // Load the updatable threat-intelligence feed, if configured.
  if (!cfg.rules_dir.empty()) {
    size_t n = threat_feed_.load(cfg.rules_dir);
    LOG_INFO("filter", "Threat feed loaded from " + cfg.rules_dir + ": " +
                           std::to_string(threat_feed_.ja3_count()) + " JA3, " +
                           std::to_string(threat_feed_.domain_count()) + " domains, " +
                           std::to_string(threat_feed_.ip_count()) + " IPs, " +
                           std::to_string(threat_feed_.signature_count()) +
                           " signatures (" + std::to_string(n) + " total)");
  }
}

void NpuFilter::set_flow_event_callback(OnFlowEvent cb) {
  flow_event_callback_ = std::move(cb);
}

static void emit_flow_event(const OnFlowEvent &cb, const FlowData *flow,
                            FlowAction action, const char *reason) {
  if (!cb)
    return;
  FlowEvent ev;
  ev.timestamp = std::chrono::system_clock::now();
  ev.connection = flow->id;
  ev.action = action;
  ev.reason = reason;
  ev.payload_size = flow->reassembled_payload.size();
  cb(ev);
}

void NpuFilter::start() {
  running = true;
  worker = std::thread(&NpuFilter::worker_loop, this);
}

void NpuFilter::stop() {
  running = false;
  if (worker.joinable())
    worker.join();
}

void NpuFilter::extract_features(FlowData *flow, std::vector<float> &features) {
  if (flow->reassembled_payload.empty()) {
    features = {0.0f, static_cast<float>(flow->length_variance),
                static_cast<float>(flow->inter_arrival_time)};
    return;
  }

  std::array<size_t, 256> counts = {0};
  for (uint8_t byte : flow->reassembled_payload)
    counts[byte]++;

  double entropy = 0.0;
  size_t total = flow->reassembled_payload.size();
  for (size_t c : counts) {
    if (c > 0) {
      double p = static_cast<double>(c) / total;
      entropy -= p * std::log2(p);
    }
  }

  features = {static_cast<float>(entropy),
              static_cast<float>(flow->length_variance),
              static_cast<float>(flow->inter_arrival_time)};
}

#ifdef WIREWOLF_USE_OPENVINO
void NpuFilter::prepare_byte_tensor(const FlowData *flow,
                                    ov::Tensor &tensor) {
  int32_t *data = tensor.data<int32_t>();
  const auto &payload = flow->reassembled_payload;
  size_t copy_len = std::min(payload.size(), CNN_INPUT_SEQ_LEN);

  for (size_t i = 0; i < copy_len; ++i)
    data[i] = static_cast<int32_t>(payload[i]);

  for (size_t i = copy_len; i < CNN_INPUT_SEQ_LEN; ++i)
    data[i] = CNN_PAD_TOKEN;
}
#endif

bool NpuFilter::detect_heartbleed(const FlowData *flow) const {
  const auto &p = flow->reassembled_payload;
  if (p.size() < 8)
    return false;

  for (size_t i = 0; i + 7 < p.size(); ++i) {
    uint8_t content_type = p[i];
    if (content_type != 0x18)
      continue;

    uint8_t major = p[i + 1];
    uint8_t minor = p[i + 2];
    if (major != 0x03 || minor > 0x03)
      continue;

    uint16_t record_len = (static_cast<uint16_t>(p[i + 3]) << 8) | p[i + 4];

    if (i + 5 + record_len > p.size())
      continue;

    if (record_len < 3)
      continue;

    uint8_t hb_type = p[i + 5];
    if (hb_type != 1 && hb_type != 2)
      continue;

    uint16_t hb_payload_len = (static_cast<uint16_t>(p[i + 6]) << 8) | p[i + 7];

    uint16_t actual_data = record_len - 3;
    if (hb_payload_len > actual_data + 16) {
      LOG_INFO("filter", "Heartbleed signature: hb_len=" +
                             std::to_string(hb_payload_len) +
                             " actual=" + std::to_string(actual_data) +
                             " at offset " + std::to_string(i));
      return true;
    }
  }
  return false;
}

bool NpuFilter::detect_spnego(const FlowData *flow) const {
  const auto &p = flow->reassembled_payload;
  static const uint8_t spnego_oid[] = {0x06, 0x06, 0x2b, 0x06,
                                       0x01, 0x05, 0x05, 0x02};
  static const uint8_t ntlmssp[] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'};

  if (p.size() >= sizeof(spnego_oid)) {
    auto it = std::search(p.begin(), p.end(), std::begin(spnego_oid),
                          std::end(spnego_oid));
    if (it != p.end())
      return true;
  }
  if (p.size() >= sizeof(ntlmssp)) {
    auto it =
        std::search(p.begin(), p.end(), std::begin(ntlmssp), std::end(ntlmssp));
    if (it != p.end())
      return true;
  }
  return false;
}

bool NpuFilter::detect_ftp_activity(const FlowData *flow) const {
  const auto &p = flow->reassembled_payload;
  if (p.size() < 10)
    return false;

  size_t scan_len = std::min(p.size(), size_t(2048));
  std::string text(p.begin(), p.begin() + scan_len);

  bool has_user = text.contains("USER ");
  bool has_pass = text.contains("PASS ");
  bool has_stor = text.contains("STOR ");

  // FTP control channel with login + upload is always suspicious
  if (has_user && has_pass && has_stor)
    return true;

  // STOR with suspicious filename patterns (info-stealers)
  if (has_stor) {
    auto pos = text.find("STOR ");
    std::string filename = text.substr(pos + 5, 200);
    auto eol = filename.find_first_of("\r\n");
    if (eol != std::string::npos)
      filename = filename.substr(0, eol);

    static const char *suspicious_patterns[] = {
        "PW_",       "password",  "Password",  "cred",     "Cred",
        "keylog",    "Keylog",    "wallet",    "Wallet",   "cookie",
        "Cookie",    "Login",     "login_",    "Contacts", "contacts",
        "token",     "Token",     "secret",    "Secret"};
    for (const char *pat : suspicious_patterns) {
      if (filename.contains(pat))
        return true;
    }
  }

  // Bot FTP pattern: multiple STOR commands in one session (automated exfil)
  if (has_stor) {
    size_t stor_count = 0;
    size_t pos = 0;
    while ((pos = text.find("STOR ", pos)) != std::string::npos) {
      stor_count++;
      pos += 5;
    }
    if (stor_count >= 2)
      return true;
  }

  return false;
}

bool NpuFilter::detect_credential_content(const FlowData *flow) const {
  const auto &p = flow->reassembled_payload;
  if (p.size() < 20)
    return false;

  // Require predominantly printable text to avoid false positives
  // on binary payloads (e.g. leaked memory from Heartbleed responses).
  size_t scan_len = std::min(p.size(), size_t(2048));
  size_t printable = 0;
  for (size_t i = 0; i < scan_len; ++i) {
    uint8_t b = p[i];
    if ((b >= 32 && b <= 126) || b == '\n' || b == '\r' || b == '\t')
      printable++;
  }
  if (static_cast<double>(printable) / scan_len < 0.85)
    return false;

  std::string text(p.begin(), p.begin() + scan_len);

  // Patterns typical of info-stealer exfiltration payloads
  int score = 0;

  // System recon markers
  if (text.contains("User Name:") ||
      text.contains("Computer Name:") ||
      text.contains("OSFullName:"))
    score += 2;

  // Credential markers
  if (text.contains("Password:") ||
      text.contains("Password="))
    score += 2;

  if (text.contains("Username:") ||
      text.contains("Username="))
    score += 1;

  // Application credential stores
  if (text.contains("Application:"))
    score += 1;

  // Protocol URIs used by credential harvesters
  // NOSONAR-justification: these are IDS detection signatures for spotting
  // credential harvesters in captured traffic — not protocols this code uses.
  static const char *proto_uris[] = {"imap://", "smtp://", "pop3://", // NOSONAR
                                      "ftp://",  "oauth://"};         // NOSONAR
  for (const char *uri : proto_uris) {
    if (text.contains(uri)) {
      score += 1;
      break;
    }
  }

  // Host + Password combination is a strong signal
  if (text.contains("Host:") &&
      text.contains("Password:"))
    score += 2;

  // Bulk email list: count lines that look like email addresses.
  // Info-stealers exfiltrate contact lists as plain email-per-line files.
  // Require strict email format to avoid false positives on binary data.
  if (score < 3) {
    auto is_email_char = [](char c) -> bool {
      return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
             (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' ||
             c == '+';
    };

    int email_count = 0;
    size_t pos = 0;
    while (pos < text.size() && email_count < 6) {
      size_t at = text.find('@', pos);
      if (at == std::string::npos || at == 0)
        break;

      // Validate local part: at least 1 email char before @
      bool valid_local = at > 0 && is_email_char(text[at - 1]);

      // Validate domain: alphanumeric chars after @, with at least one dot
      bool valid_domain = false;
      if (valid_local && at + 2 < text.size()) {
        size_t dom_end = at + 1;
        bool has_dot = false;
        while (dom_end < text.size() && (is_email_char(text[dom_end]))) {
          if (text[dom_end] == '.')
            has_dot = true;
          dom_end++;
        }
        // Domain must be at least "x.xx" (4 chars with a dot)
        valid_domain = has_dot && (dom_end - at - 1) >= 4;
      }

      if (valid_local && valid_domain)
        email_count++;
      pos = at + 1;
    }
    if (email_count >= 5)
      score += 3; // 5+ valid emails in a list is a strong exfil signal
  }

  return score >= 3;
}

bool NpuFilter::detect_benign_http(const FlowData *flow) const {
  const auto &p = flow->reassembled_payload;
  if (p.size() < 16)
    return false;

  std::string start(p.begin(), p.begin() + std::min(p.size(), size_t(4)));
  bool is_request =
      (start.substr(0, 3) == "GET" || start.substr(0, 4) == "POST" ||
       start.substr(0, 4) == "HEAD" || start.substr(0, 3) == "PUT");
  if (!is_request)
    return false;

  auto header_end = std::search(p.begin(), p.end(), std::begin("\r\n\r\n") - 1,
                                std::end("\r\n\r\n") - 2);
  size_t request_end =
      (header_end != p.end()) ? std::distance(p.begin(), header_end) : p.size();

  auto first_line_end = std::find(p.begin(), p.begin() + request_end, '\r');
  if (first_line_end == p.begin() + request_end)
    first_line_end = std::find(p.begin(), p.begin() + request_end, '\n');

  std::string first_line(p.begin(), first_line_end);

  static const char *injection_markers[] = {
      "{{",   "<script", "<img",   "<svg",         "onerror", "onload",
      "' OR", "\" OR",   "; DROP", "UNION SELECT", "$(",      "`",
      "||",   "../",     "..\\",   "%00",          "%0a",     "%0d"};

  for (const char *marker : injection_markers) {
    if (first_line.contains(marker))
      return false;
  }

  return true;
}

bool NpuFilter::detect_http_bruteforce(const FlowData *flow) const {
  const auto &p = flow->reassembled_payload;
  if (p.size() < 50)
    return false;

  size_t scan_len = std::min(p.size(), size_t(8192));
  std::string text(p.begin(), p.begin() + scan_len);

  // HTTP credential brute force = many POSTs to an AUTHENTICATION endpoint.
  // Counting *any* POST is far too broad: OCSP responders, REST/AJAX APIs and
  // keepalive/pipelined HTTP all post repeatedly to non-auth paths (e.g.
  // ocsp.digicert.com), which produced false "Brute Force" alerts. So we only
  // count POSTs whose request-line path looks like a login/auth endpoint.
  static const char *auth_paths[] = {
      "login",   "log-in",  "signin",   "sign-in", "logon",  "auth",
      "wp-login", "wp-admin", "/admin",  "session", "oauth",  "/token",
      "account", "/api/login", "j_security_check"};
  auto is_auth_path = [&](const std::string &lower) {
    for (const char *kw : auth_paths)
      if (lower.contains(kw))
        return true;
    return false;
  };

  size_t auth_post_count = 0;
  size_t pos = 0;
  while ((pos = text.find("POST ", pos)) != std::string::npos) {
    const size_t path_start = pos + 5;
    size_t path_end = text.find(' ', path_start); // POST <path> HTTP/1.1
    if (path_end == std::string::npos)
      path_end = std::min(path_start + 256, text.size());
    std::string path = text.substr(path_start, path_end - path_start);
    std::transform(path.begin(), path.end(), path.begin(), ::tolower);
    if (is_auth_path(path))
      auth_post_count++;
    pos = path_start;
  }

  // 5+ login POSTs in one flow is a strong credential-brute-force signal.
  return auth_post_count >= 5;
}

bool NpuFilter::detect_smb_exploit(const FlowData *flow) const {
  const auto &p = flow->reassembled_payload;
  if (p.size() < 100)
    return false;

  // Check that this is SMB traffic (port 445 in either direction)
  auto bswap16 = [](uint16_t v) -> uint16_t { return (v >> 8) | (v << 8); };
  uint16_t src_port = bswap16(flow->id.src_port);
  uint16_t dst_port = bswap16(flow->id.dst_port);
  if (src_port != 445 && dst_port != 445)
    return false;

  // Look for SMBv1 header: NetBIOS session (4 bytes) + \xFFSMB magic
  bool has_smb_header = false;
  bool has_tree_connect_ipc = false;
  bool has_trans_command = false;
  bool has_large_write = false;
  size_t total_write_bytes = 0;

  for (size_t i = 0; i + 8 < p.size(); ++i) {
    // SMBv1 magic: \xFFSMB at offset 4 of NetBIOS session frame
    if (p[i] == 0xFF && p[i + 1] == 'S' && p[i + 2] == 'M' &&
        p[i + 3] == 'B') {
      has_smb_header = true;
      uint8_t cmd = p[i + 4]; // SMB command byte

      // TreeConnect (0x75) — look for IPC$ share
      if (cmd == 0x75) {
        // Scan for "IPC" near this location in both ASCII and UTF-16LE
        size_t search_end = std::min(i + 200, p.size());
        for (size_t j = i + 4; j + 3 < search_end; ++j) {
          // ASCII: IPC (0x49 0x50 0x43)
          if (p[j] == 'I' && p[j + 1] == 'P' && p[j + 2] == 'C') {
            has_tree_connect_ipc = true;
            break;
          }
          // UTF-16LE: I\x00P\x00C\x00 (0x49 0x00 0x50 0x00 0x43 0x00)
          if (j + 5 < search_end &&
              p[j] == 'I' && p[j + 1] == 0x00 &&
              p[j + 2] == 'P' && p[j + 3] == 0x00 &&
              p[j + 4] == 'C' && p[j + 5] == 0x00) {
            has_tree_connect_ipc = true;
            break;
          }
        }
      }

      // Transaction commands used by EternalBlue:
      // Trans (0x25), Trans2 (0x32), NT Trans (0xA0)
      if (cmd == 0x25 || cmd == 0x32 || cmd == 0xA0)
        has_trans_command = true;

      // Write commands used for payload delivery:
      // Write (0x2F), WriteAndX (0x33), Write_Raw (0x1D)
      if (cmd == 0x2F || cmd == 0x33 || cmd == 0x1D) {
        has_large_write = true;
        // Estimate: each occurrence usually sends ~1460 bytes
        total_write_bytes += 1400;
      }
    }
  }

  if (!has_smb_header)
    return false;

  // SMB exploit pattern: require IPC$ + Trans/Trans2 + substantial payload.
  // Normal SMB sessions have IPC$ + Trans for pipe operations but with
  // small payloads (<1KB). Exploit chains deliver large payloads (>10KB)
  // through the IPC$ pipe after the Trans2 overflow.
  if (has_tree_connect_ipc && has_trans_command &&
      flow->reassembled_payload.size() > 10000) {
    LOG_INFO("filter", "SMB exploit signature: IPC$=" +
                           std::to_string(has_tree_connect_ipc) +
                           " Trans=" + std::to_string(has_trans_command) +
                           " LargeWrite=" + std::to_string(has_large_write) +
                           " payload=" +
                           std::to_string(flow->reassembled_payload.size()));
    return true;
  }

  return false;
}

bool NpuFilter::detect_rat_protocol(const FlowData *flow) const {
  const auto &p = flow->reassembled_payload;
  if (p.size() < 20)
    return false;

  // Only check non-standard ports (RATs use custom ports, not 80/443/etc.)
  auto bswap16 = [](uint16_t v) -> uint16_t { return (v >> 8) | (v << 8); };
  uint16_t src_port = bswap16(flow->id.src_port);
  uint16_t dst_port = bswap16(flow->id.dst_port);
  bool standard_port = false;
  for (uint16_t sp : {80, 443, 8080, 8443, 22, 21, 25, 53, 110, 143, 445,
                      993, 995, 3306, 3389, 5432}) {
    if (src_port == sp || dst_port == sp) {
      standard_port = true;
      break;
    }
  }
  if (standard_port)
    return false;

  // Scan the first portion of the payload for RAT protocol patterns.
  size_t scan_len = std::min(p.size(), size_t(4096));
  std::string text(p.begin(), p.begin() + scan_len);

  int score = 0;

  // --- njRAT / Bladabindi pattern ---
  // Format: <len_digits>\x00<cmd>|'|'|<base64_data>
  // The |'|'| delimiter is a unique njRAT fingerprint.
  {
    size_t delim_count = 0;
    size_t pos = 0;
    while ((pos = text.find("|'|'|", pos)) != std::string::npos) {
      delim_count++;
      pos += 5;
    }
    if (delim_count >= 3)
      score += 4; // very strong njRAT signal
  }

  // --- Generic RAT command structure ---
  // Many RATs use a length-prefix + null + short command pattern:
  // <digits>\x00<2-4 char command>
  {
    size_t cmd_count = 0;
    for (size_t i = 0; i + 5 < scan_len; ++i) {
      if (p[i] == 0x00 && i > 0 && i < 10) {
        // Check if bytes before null are ASCII digits (length prefix)
        bool all_digits = true;
        for (size_t j = 0; j < i; ++j) {
          if (p[j] < '0' || p[j] > '9') {
            all_digits = false;
            break;
          }
        }
        if (all_digits) {
          // Check if bytes after null are ASCII letters (command)
          bool has_cmd = true;
          size_t cmd_end = std::min(i + 4, scan_len);
          for (size_t j = i + 1; j < cmd_end; ++j) {
            if (!((p[j] >= 'a' && p[j] <= 'z') ||
                  (p[j] >= 'A' && p[j] <= 'Z'))) {
              has_cmd = false;
              break;
            }
          }
          if (has_cmd)
            cmd_count++;
        }
      }
    }
    if (cmd_count >= 2)
      score += 2;
  }

  // --- System recon markers in base64-decoded or cleartext ---
  // RATs exfiltrate hostname, username, OS info
  static const char *recon_markers[] = {
      "Administrator", "\\Desktop\\",   "\\Users\\",
      "\\AppData\\",   "TEMP",          ".exe",
      "\\Windows\\",   "cmd.exe",       "powershell",
      "tasklist",      "ipconfig",      "systeminfo",
  };
  int recon_hits = 0;
  for (const char *marker : recon_markers) {
    if (text.contains(marker))
      recon_hits++;
  }
  if (recon_hits >= 2)
    score += 2;

  // --- Base64-encoded content with pipe/delimiter structure ---
  // Many RATs base64-encode payloads between delimiters
  {
    size_t b64_runs = 0;
    size_t i = 0;
    while (i < scan_len) {
      // Count consecutive base64 characters
      size_t run_start = i;
      while (i < scan_len &&
             ((p[i] >= 'A' && p[i] <= 'Z') || (p[i] >= 'a' && p[i] <= 'z') ||
              (p[i] >= '0' && p[i] <= '9') || p[i] == '+' || p[i] == '/' ||
              p[i] == '=')) {
        i++;
      }
      if (i - run_start >= 20) // 20+ char base64 run
        b64_runs++;
      i++;
    }
    if (b64_runs >= 3)
      score += 1; // multiple base64 blocks suggest encoded C2 data
  }

  if (score >= 4) {
    LOG_INFO("filter", "RAT protocol signature: score=" +
                           std::to_string(score) + " port=" +
                           std::to_string(dst_port != 0 ? dst_port : src_port) +
                           " payload=" +
                           std::to_string(flow->reassembled_payload.size()));
    return true;
  }

  return false;
}

bool NpuFilter::detect_obfuscated_injection(const FlowData *flow) const {
  // Scans the canonicalized payload (URL/unicode decoded, comments stripped,
  // lowercased). Catches attacks that obfuscation hid from the raw-text
  // detectors. Escalates to the LLM, which makes the final call — so this
  // boosts recall without bypassing the false-positive guard.
  const std::string &n = flow->normalized_payload;
  if (n.size() < 6)
    return false;

  static const char *markers[] = {
      // SQLi
      "' or 1=1", "\" or 1=1", "' or '1'='1", "union select", "; drop table",
      "waitfor delay", "benchmark(", "sleep(", "extractvalue(", "updatexml(",
      "information_schema",
      // XSS
      "<script", "javascript:", "onerror=", "onload=", "onmouseover=",
      "<svg", "<img src=", "document.cookie", "string.fromcharcode(",
      // Command injection / reverse shell
      ";cat /etc", "|cat /etc", "/bin/sh", "/bin/bash -i", "; nc ", "| nc ",
      "$(", "`id`", "; wget http", "; curl http", "powershell -e",
      "/dev/tcp/",
      // Path traversal / LFI
      "../../", "..\\..\\", "/etc/passwd", "/etc/shadow", "php://filter",
      "php://input", "/proc/self/environ",
      // Template / expression injection
      "{{7*7}}", "${jndi:", "${(", "#{", "t(java.lang.runtime)",
      // Shellshock / deserialization
      "() {", "ac ed 00 05", "__proto__",
      // XXE
      "<!entity", "system \"file:", "system \"http",
  };

  for (const char *m : markers) {
    if (n.contains(m)) {
      LOG_INFO("filter", std::string("Obfuscation-decoded injection marker: '") +
                             m + "'");
      return true;
    }
  }
  return false;
}

int NpuFilter::inspect_tls(FlowData *flow) const {
  TlsInfo tls;
  if (!parse_tls_client_hello(flow->reassembled_payload, tls))
    return 0; // not a TLS ClientHello

  flow->tls_sni = tls.sni;
  flow->tls_ja3 = tls.ja3_hash;

  // Visibility: log every TLS handshake's destination + fingerprint, even
  // though the payload itself is encrypted.
  LOG_INFO("tls", "ClientHello SNI='" + (tls.sni.empty() ? std::string("(none)") : tls.sni) +
                      "' JA3=" + tls.ja3_hash);

  // Known-malware JA3 fingerprints. Built-in sample set plus any loaded from
  // the threat-intel feed (bad_ja3.txt). These identify the client TLS stack
  // regardless of destination or certificate.
  static const char *bad_ja3[] = {
      "a0e9f5d64349fb13191bc781f81f42e1", // Cobalt Strike (common default)
      "72a589da586844d7f0818ce684948eea", // Trickbot
      "6734f37431670b3ab4292b8f60f29984", // Metasploit Meterpreter
  };
  for (const char *b : bad_ja3) {
    if (tls.ja3_hash == b) {
      flow->protocol_tag = "Malicious TLS Client";
      return 1;
    }
  }
  if (threat_feed_.is_bad_ja3(tls.ja3_hash)) {
    LOG_WARN("tls", "Threat-feed JA3 match: " + tls.ja3_hash);
    flow->protocol_tag = "Malicious TLS Client";
    return 1;
  }

  // Cleartext SNI against the threat-intel domain blocklist (C2/phishing).
  if (threat_feed_.is_bad_domain(tls.sni)) {
    LOG_WARN("tls", "Threat-feed domain match: SNI=" + tls.sni);
    flow->protocol_tag = "C2 Beaconing";
    return 1;
  }

  // SNI heuristics (cleartext destination, even over HTTPS):
  auto sni_suspicious = [&](const std::string &s) -> bool {
    if (s.empty())
      return false; // missing SNI alone is too noisy to flag
    // raw-IP SNI (legitimate clients send hostnames, not IPs)
    bool all_ipish = !s.empty();
    for (char c : s)
      if (!((c >= '0' && c <= '9') || c == '.')) { all_ipish = false; break; }
    if (all_ipish)
      return true;
    // DGA-like: a long label with high digit ratio / high entropy
    size_t dot = s.find('.');
    std::string label = (dot == std::string::npos) ? s : s.substr(0, dot);
    if (label.size() >= 16) {
      size_t digits = 0;
      size_t consonants = 0;
      for (char c : label) {
        if (c >= '0' && c <= '9') digits++;
        else if (strchr("bcdfghjklmnpqrstvwxz", c)) consonants++;
      }
      double dr = static_cast<double>(digits) / label.size();
      double cr = static_cast<double>(consonants) / label.size();
      if (dr > 0.3 || cr > 0.75)
        return true; // looks algorithmically generated
    }
    return false;
  };

  if (sni_suspicious(tls.sni)) {
    flow->protocol_tag = "Suspicious TLS";
    return 1;
  }

  return 2; // benign TLS — don't waste the LLM on encrypted bytes
}

bool NpuFilter::statistical_filter(const std::vector<float> &features,
                                   const FlowData *flow) {
  float entropy = features[0];
  float variance = features[1];
  float inter_arrival = features[2];

  if (entropy > cfg.entropy_high_threshold)
    return true;

  if (entropy < cfg.entropy_low_threshold &&
      flow->reassembled_payload.size() > cfg.min_payload_for_low_entropy)
    return true;

  if (variance > cfg.variance_threshold)
    return true;

  if (inter_arrival < cfg.inter_arrival_floor && inter_arrival > 0.0f &&
      flow->packet_count > cfg.min_packet_count_for_flood)
    return true;

  if (!flow->reassembled_payload.empty() &&
      flow->reassembled_payload.size() < 4096) {
    size_t suspicious_chars = 0;
    for (uint8_t b : flow->reassembled_payload) {
      if (b == '\'' || b == '"' || b == '{' || b == '}' || b == '|' || b == '`')
        suspicious_chars++;
    }
    double ratio = static_cast<double>(suspicious_chars) /
                   flow->reassembled_payload.size();
    if (ratio > 0.05)
      return true;
  }

  return false;
}

// Priority for the LLM-bound queue. A flow a detector already named
// (protocol_tag set, e.g. Heartbleed/Brute Force/RAT C2) is higher-confidence
// than generic statistical suspicion, so under load the emergency drop in
// ThreadSafeQueue sheds the least-certain flows first and keeps the scary ones.
static int flow_priority(const FlowData *f) {
  // A flow a detector already named (protocol_tag) OR one the behavioral Markov
  // escalated both outrank generic statistical suspicion, so under load the
  // emergency drop in ThreadSafeQueue sheds the least-certain flows first.
  return (!f->protocol_tag.empty() || f->behavioral_suspect) ? 2 : 1;
}

void NpuFilter::worker_loop() {
  while (running) {
    auto flow_opt = input_queue.pop();
    if (!flow_opt)
      continue;

    FlowPtr flow = std::move(flow_opt.value());

    if (flow->reassembled_payload.empty()) {
      LOG_DEBUG("filter", "DROP empty payload");
      filtered_count.fetch_add(1, std::memory_order::relaxed);
      emit_flow_event(flow_event_callback_, flow.get(), FlowAction::Filtered, "empty");
      continue;
    }

    if (seen_payload_hashes_.size() > MAX_DEDUP_HASHES)
      seen_payload_hashes_.clear();

    FlowData *raw = flow.get();

    // Anti-evasion: canonicalize the payload once (URL/unicode decode,
    // comment strip, case/whitespace fold) so obfuscated attacks can be
    // matched by the signature stage and seen by the LLM.
    flow->normalized_payload = normalize_payload(flow->reassembled_payload);

    // Encrypted-traffic analysis: if this is a TLS handshake, inspect its
    // metadata (SNI + JA3) instead of the (useless) encrypted payload.
    // IMPORTANT: only short-circuit as "benign TLS" if no exploit signature
    // rides on top of the handshake. Heartbleed (CVE-2014-0160) travels over
    // TLS/443, so we MUST run that signature before dropping the flow as
    // benign TLS — otherwise the TLS fast-path masks the attack.
    int tls = inspect_tls(raw);
    if (tls == 2 && detect_heartbleed(raw))
      tls = 0; // exploit present on the TLS channel; fall through to detectors
    if (tls == 1) {
      // Suspicious TLS (bad JA3 or DGA/raw-IP SNI). protocol_tag is set.
      LOG_INFO("filter", "PASS suspicious TLS (" + flow->protocol_tag +
                             "): SNI='" + flow->tls_sni + "' JA3=" + flow->tls_ja3);
      passed_count.fetch_add(1, std::memory_order::relaxed);
      emit_flow_event(flow_event_callback_, raw, FlowAction::PassedToLLM, "tls-suspicious");
      output_queue.push(std::move(flow), flow_priority(raw));
      continue;
    } else if (tls == 2) {
      // Benign TLS — the encrypted payload tells the LLM nothing; drop it.
      LOG_DEBUG("filter", "DROP benign TLS (SNI='" + flow->tls_sni + "')");
      filtered_count.fetch_add(1, std::memory_order::relaxed);
      emit_flow_event(flow_event_callback_, raw, FlowAction::Filtered, "tls-benign");
      continue;
    }

    // Threat-intelligence feed: curated content signatures + IP reputation.
    // A hit escalates straight to the LLM for confirmation (the feed is a
    // high-recall pre-filter; the LLM remains the arbiter).
    if (!threat_feed_.empty()) {
      auto ip_to_str = [](uint32_t ip) {
        auto *b = reinterpret_cast<const uint8_t *>(&ip);
        return std::to_string(b[0]) + "." + std::to_string(b[1]) + "." +
               std::to_string(b[2]) + "." + std::to_string(b[3]);
      };
      const ContentSignature *sig =
          threat_feed_.match_signature(flow->normalized_payload);
      bool bad_ip = threat_feed_.is_bad_ip(ip_to_str(flow->id.src_ip)) ||
                    threat_feed_.is_bad_ip(ip_to_str(flow->id.dst_ip));
      if (sig || bad_ip) {
        // Live NIDS: a content-signature hit is a deterministic verdict, so
        // tag the flow with the matched threat type. The LLM stage sees the
        // protocol_tag and emits the alert directly WITHOUT running inference
        // (fast path) — this is how "fast detectors decide" keeps live capture
        // real-time. Forensic mode leaves the tag unset so the LLM still
        // arbitrates the hit for deeper confirmation/explanation.
        if (sig && !cfg.is_forensic()) {
          flow->protocol_tag = sig->severity; // threat_type drives CVSS lookup
          LOG_INFO("filter", "DECIDE (live) signature: " + sig->name + " -> " +
                                 sig->severity + " (skipping LLM)");
        } else {
          LOG_INFO("filter", std::string("PASS threat-intel ") +
                                 (sig ? ("signature: " + sig->name)
                                      : std::string("bad-IP")) +
                                 " -> LLM");
        }
        passed_count.fetch_add(1, std::memory_order::relaxed);
        emit_flow_event(flow_event_callback_, raw, FlowAction::PassedToLLM,
                        "threat-intel");
        output_queue.push(std::move(flow), flow_priority(raw));
        continue;
      }
    }

    bool is_heartbleed = detect_heartbleed(raw);

    if (is_heartbleed) {
      size_t dedup_hash = 0;
      hash_combine(dedup_hash, flow->id.dst_ip);
      hash_combine(dedup_hash, flow->id.dst_port);
      hash_combine(dedup_hash, size_t(0xDEADBEEF));
      if (!seen_payload_hashes_.insert(dedup_hash).second) {
        LOG_DEBUG("filter", "DROP duplicate Heartbleed flow");
        dedup_count.fetch_add(1, std::memory_order::relaxed);
        filtered_count.fetch_add(1, std::memory_order::relaxed);
        emit_flow_event(flow_event_callback_, raw, FlowAction::Filtered, "dedup");
        continue;
      }

      LOG_INFO("filter",
               "PASS Heartbleed signature detected, bypassing filters");
      flow->protocol_tag = "Heartbleed";
      passed_count.fetch_add(1, std::memory_order::relaxed);
      emit_flow_event(flow_event_callback_, raw, FlowAction::PassedToLLM, "heartbleed");
      output_queue.push(std::move(flow), flow_priority(raw));
      continue;
    }

    if (detect_smb_exploit(raw)) {
      uint32_t ip_lo = std::min(flow->id.src_ip, flow->id.dst_ip);
      uint32_t ip_hi = std::max(flow->id.src_ip, flow->id.dst_ip);
      size_t dedup_hash = 0;
      hash_combine(dedup_hash, ip_lo);
      hash_combine(dedup_hash, ip_hi);
      hash_combine(dedup_hash, size_t(0xDEAD0017));
      if (!seen_payload_hashes_.insert(dedup_hash).second) {
        LOG_DEBUG("filter", "DROP duplicate SMB exploit flow");
        dedup_count.fetch_add(1, std::memory_order::relaxed);
        filtered_count.fetch_add(1, std::memory_order::relaxed);
        emit_flow_event(flow_event_callback_, raw, FlowAction::Filtered, "dedup");
        continue;
      }

      LOG_INFO("filter",
               "PASS SMB exploit signature detected, bypassing filters");
      flow->protocol_tag = "SMB Exploit";
      passed_count.fetch_add(1, std::memory_order::relaxed);
      emit_flow_event(flow_event_callback_, raw, FlowAction::PassedToLLM, "smb-exploit");
      output_queue.push(std::move(flow), flow_priority(raw));
      continue;
    }

    if (detect_spnego(raw)) {
      LOG_DEBUG("filter", "DROP GSS-SPNEGO/Kerberos negotiation");
      filtered_count.fetch_add(1, std::memory_order::relaxed);
      emit_flow_event(flow_event_callback_, raw, FlowAction::Filtered, "SPNEGO");
      continue;
    }

    if (detect_http_bruteforce(raw)) {
      LOG_INFO("filter",
               "PASS HTTP brute force pattern detected, bypassing filters");
      flow->protocol_tag = "Brute Force";
      passed_count.fetch_add(1, std::memory_order::relaxed);
      emit_flow_event(flow_event_callback_, raw, FlowAction::PassedToLLM, "http-bruteforce");
      output_queue.push(std::move(flow), flow_priority(raw));
      continue;
    }

    if (detect_benign_http(raw)) {
      LOG_DEBUG("filter", "DROP benign HTTP request");
      filtered_count.fetch_add(1, std::memory_order::relaxed);
      emit_flow_event(flow_event_callback_, raw, FlowAction::Filtered, "benign HTTP");
      continue;
    }

    if (detect_credential_content(raw)) {
      const bool ext = dst_is_external(raw->id.dst_ip);
      LOG_INFO("filter",
               "PASS credential content detected, bypassing filters");
      flow->protocol_tag = ext ? "Data Exfiltration" : "Suspicious Transfer";
      passed_count.fetch_add(1, std::memory_order::relaxed);
      emit_flow_event(flow_event_callback_, raw, FlowAction::PassedToLLM, "credential-content");
      output_queue.push(std::move(flow), flow_priority(raw));
      continue;
    }

    if (detect_ftp_activity(raw)) {
      const bool ext = dst_is_external(raw->id.dst_ip);
      LOG_INFO("filter",
               "PASS FTP transfer pattern detected, bypassing filters");
      // Exfiltration only if the upload leaves the network; an internal->
      // internal FTP STOR is a suspicious transfer, not exfiltration.
      flow->protocol_tag = ext ? "Data Exfiltration" : "Suspicious Transfer";
      passed_count.fetch_add(1, std::memory_order::relaxed);
      emit_flow_event(flow_event_callback_, raw, FlowAction::PassedToLLM, "ftp-exfil");
      output_queue.push(std::move(flow), flow_priority(raw));
      continue;
    }

    if (detect_rat_protocol(raw)) {
      auto bswap16_ = [](uint16_t v) -> uint16_t {
        return (v >> 8) | (v << 8);
      };
      uint16_t sp = bswap16_(flow->id.src_port);
      uint16_t dp = bswap16_(flow->id.dst_port);
      uint32_t server_ip =
          (sp < dp) ? flow->id.src_ip : flow->id.dst_ip;
      uint16_t server_port = std::min(sp, dp);
      size_t dedup_hash = 0;
      hash_combine(dedup_hash, server_ip);
      hash_combine(dedup_hash, static_cast<size_t>(server_port));
      hash_combine(dedup_hash, size_t(0xDEADC2C2));
      if (!seen_payload_hashes_.insert(dedup_hash).second) {
        LOG_DEBUG("filter", "DROP duplicate RAT C2 flow");
        dedup_count.fetch_add(1, std::memory_order::relaxed);
        filtered_count.fetch_add(1, std::memory_order::relaxed);
        emit_flow_event(flow_event_callback_, raw, FlowAction::Filtered, "dedup");
        continue;
      }

      LOG_INFO("filter",
               "PASS RAT C2 protocol detected, bypassing filters");
      flow->protocol_tag = "RAT C2";
      passed_count.fetch_add(1, std::memory_order::relaxed);
      emit_flow_event(flow_event_callback_, raw, FlowAction::PassedToLLM, "rat-c2");
      output_queue.push(std::move(flow), flow_priority(raw));
      continue;
    }

    std::vector<float> features;
    extract_features(raw, features);

    // Anti-evasion: if canonicalization revealed an injection signature that
    // obfuscation had hidden, escalate to the LLM for confirmation.
    // Anti-evasion escalation: de-obfuscated injection signature found.
    // OR'd with the model/statistical verdict below so it can't be clobbered.
    bool obfuscated = detect_obfuscated_injection(raw);
    if (obfuscated)
      LOG_INFO("filter", "PASS de-obfuscated injection -> LLM");

    // A behavioral-Markov escalation forces the flow through to the LLM for
    // adjudication regardless of the statistical verdict (the signal is about
    // flow timing/size, not payload content).
    bool suspicious = obfuscated || raw->behavioral_suspect;

#ifdef WIREWOLF_USE_OPENVINO
    if (openvino_available) {
      try {
        ov::Tensor input_tensor(ov::element::i32,
                                {1, CNN_INPUT_SEQ_LEN});
        prepare_byte_tensor(raw, input_tensor);

        infer_request.set_input_tensor(input_tensor);
        infer_request.infer();

        ov::Tensor output_tensor = infer_request.get_output_tensor();
        float prediction = output_tensor.data<float>()[0];
        suspicious = suspicious || (prediction > cfg.npu_threshold);
      } catch (const std::exception &e) {
        LOG_WARN("filter",
                 std::string("OpenVINO inference failed, falling back: ") +
                     e.what());
        suspicious = suspicious || statistical_filter(features, raw);
      }
    } else {
      suspicious = suspicious || statistical_filter(features, raw);
    }
#else
    suspicious = suspicious || statistical_filter(features, raw);
#endif

    if (suspicious && !flow->reassembled_payload.empty()) {
      size_t printable = 0;
      for (uint8_t b : flow->reassembled_payload) {
        if ((b >= 32 && b <= 126) || b == '\n' || b == '\r' || b == '\t')
          printable++;
      }
      double text_ratio =
          static_cast<double>(printable) / flow->reassembled_payload.size();
      if (text_ratio < 0.85) {
        LOG_DEBUG(
            "filter",
            "DROP binary payload (text_ratio=" + std::to_string(text_ratio) +
                " size=" + std::to_string(flow->reassembled_payload.size()) +
                ")");
        filtered_count.fetch_add(1, std::memory_order::relaxed);
        emit_flow_event(flow_event_callback_, raw, FlowAction::Filtered, "binary");
        continue;
      }
    }

    if (suspicious) {
      size_t dedup_hash = 0;
      hash_combine(dedup_hash, flow->id.dst_ip);
      hash_combine(dedup_hash, flow->id.dst_port);
      size_t hash_len =
          std::min(flow->reassembled_payload.size(), size_t(256));
      for (size_t i = 0; i < hash_len; ++i)
        hash_combine(dedup_hash,
                     static_cast<size_t>(flow->reassembled_payload[i]));

      if (!seen_payload_hashes_.insert(dedup_hash).second) {
        LOG_DEBUG("filter",
                  "DROP duplicate payload (dedup hash collision) size=" +
                      std::to_string(flow->reassembled_payload.size()));
        dedup_count.fetch_add(1, std::memory_order::relaxed);
        filtered_count.fetch_add(1, std::memory_order::relaxed);
        emit_flow_event(flow_event_callback_, raw, FlowAction::Filtered, "dedup");
        continue;
      }

      LOG_DEBUG("filter", "PASS entropy=" + std::to_string(features[0]) +
                              " var=" + std::to_string(features[1]) +
                              " iat=" + std::to_string(features[2]) + " size=" +
                              std::to_string(flow->reassembled_payload.size()));
      passed_count.fetch_add(1, std::memory_order::relaxed);
      emit_flow_event(flow_event_callback_, raw, FlowAction::PassedToLLM, "anomaly");
      output_queue.push(std::move(flow), flow_priority(raw));
    } else {
      LOG_DEBUG("filter", "DROP entropy=" + std::to_string(features[0]) +
                              " var=" + std::to_string(features[1]) +
                              " iat=" + std::to_string(features[2]));
      filtered_count.fetch_add(1, std::memory_order::relaxed);
      emit_flow_event(flow_event_callback_, raw, FlowAction::Filtered, "statistical");
    }
  }
}
