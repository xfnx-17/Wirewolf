#include "tcp_reassembly.hpp"
#include "logger.hpp"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <fstream>
#include <functional>
#include <tuple>
#include <vector>

#ifdef WIREWOLF_USE_WINDIVERT
#include <windivert.h>
#endif

// Defined later in this file; used by the flow-completion paths above it.
static bool looks_like_bittorrent(const std::vector<uint8_t> &p);

static std::string json_escape(const std::string &s) {
  std::string out;
  out.reserve(s.size() + 16);
  for (char c : s) {
    switch (c) {
    case '"':  out += "\\\""; break;
    case '\\': out += "\\\\"; break;
    case '\n': out += "\\n";  break;
    case '\r': out += "\\r";  break;
    case '\t': out += "\\t";  break;
    default:
      if (static_cast<unsigned char>(c) < 0x20) {
        char buf[8];
        std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
        out += buf;
      } else {
        out += c;
      }
    }
  }
  return out;
}

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>

#define ETHERTYPE_IP 0x0800

struct ether_header {
  uint8_t ether_dhost[6];
  uint8_t ether_shost[6];
  uint16_t ether_type;
};

struct iphdr {
  uint8_t ihl : 4;
  uint8_t version : 4;
  uint8_t tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
};

struct tcphdr {
  uint16_t source;
  uint16_t dest;
  uint32_t seq;
  uint32_t ack_seq;
  uint8_t offset_res; // bits 4-7: doff, bits 0-3: res1
  uint8_t flags;      // bit 0: fin, 1: syn, 2: rst, 3: psh, 4: ack, 5: urg ...
  uint16_t window;
  uint16_t check;
  uint16_t urg_ptr;

  inline uint32_t get_doff() const { return (offset_res >> 4) & 0x0F; }
  inline bool get_fin() const { return (flags & 0x01) != 0; }
  inline bool get_syn() const { return (flags & 0x02) != 0; }
  inline bool get_rst() const { return (flags & 0x04) != 0; }
  inline bool get_psh() const { return (flags & 0x08) != 0; }
  inline bool get_ack() const { return (flags & 0x10) != 0; }
  inline bool get_urg() const { return (flags & 0x20) != 0; }
};
#else
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#endif

static inline bool seq_before(uint32_t a, uint32_t b) {
  return static_cast<int32_t>(a - b) < 0;
}

static inline bool seq_after(uint32_t a, uint32_t b) {
  return seq_before(b, a);
}

TcpReassembler::TcpReassembler(const WirewolfConfig &config,
                               ThreadSafeQueue<FlowPtr> &out_queue)
    : output_queue(out_queue), cfg(config) {

  if (!cfg.threat_proxy_db.empty()) {
    if (proxy_db_.load(cfg.threat_proxy_db))
      LOG_INFO("intel", "Threat-intel proxy DB loaded: " + cfg.threat_proxy_db);
    else
      LOG_WARN("intel", "Failed to load threat-intel DB: " + cfg.threat_proxy_db);
  }

  // Behavioral C2 Markov models (clean-room, trained offline on CTU-13).
  if (!cfg.behavioral_models_dir.empty()) {
    std::string dir = cfg.behavioral_models_dir;
    if (dir.back() != '/' && dir.back() != '\\')
      dir += '/';
    std::ifstream bf(dir + "behavioral.botnet.model");
    std::ifstream nf(dir + "behavioral.normal.model");
    if (bf && nf) {
      std::string fp_b;
      std::string fp_n;
      beh_botnet_ = behavioral::MarkovModel::load(bf, &fp_b);
      beh_normal_ = behavioral::MarkovModel::load(nf, &fp_n);
      behavioral_ready_ = true;
      const std::string want = beh_cfg_.fingerprint();
      if (fp_b != want)
        LOG_WARN("behavioral",
                 "Model/runtime config fingerprint mismatch (encoding may not "
                 "match training): model='" + fp_b + "' runtime='" + want + "'");
      LOG_INFO("behavioral", "Behavioral C2 models loaded from " +
                                 cfg.behavioral_models_dir + " (threshold " +
                                 std::to_string(cfg.behavioral_threshold) + ")");
    } else {
      LOG_WARN("behavioral", "Could not load behavioral models from " +
                                 cfg.behavioral_models_dir);
    }
  }

#ifdef WIREWOLF_USE_WINDIVERT
  if (cfg.use_windivert) {
    // Inline mode: intercept packets in the Windows TCP/IP stack at the
    // NETWORK layer. Packets are diverted from the stack to us; we inspect
    // and then re-inject (allow) or drop (block). Requires Administrator.
    LOG_INFO("divert", "Opening WinDivert (filter='" + cfg.windivert_filter +
                           "', inline_block=" +
                           (cfg.inline_block ? "on" : "off") + ")");
    divert_handle_ = WinDivertOpen(cfg.windivert_filter.c_str(),
                                   WINDIVERT_LAYER_NETWORK, 0, 0);
    if (divert_handle_ == INVALID_HANDLE_VALUE) {
      divert_handle_ = nullptr;
      DWORD err = GetLastError();
      throw std::runtime_error(
          "WinDivertOpen failed (error " + std::to_string(err) +
          "). Run as Administrator; ensure the WinDivert driver is present.");
    }
    LOG_INFO("divert", "WinDivert handle ready (inline NETWORK layer)");
    return;
  }
#endif

  char errbuf[PCAP_ERRBUF_SIZE];
  const char *device = cfg.interface.c_str();

  bool is_offline = cfg.is_offline_capture();

  if (is_offline) {
    LOG_INFO("pcap", "Opening offline capture: " + cfg.interface);
    handle = pcap_open_offline(device, errbuf);
    if (!handle) {
      throw std::runtime_error(std::string("pcap_open_offline failed: ") +
                               errbuf);
    }
  } else {
    LOG_INFO("pcap", "Opening live interface: " + cfg.interface);
    handle = pcap_open_live(device, 65535, cfg.promiscuous ? 1 : 0, 1000, errbuf);
    if (!handle) {
      throw std::runtime_error(std::string("pcap_open_live failed: ") + errbuf);
    }
  }

  int datalink = pcap_datalink(handle);
  if (datalink != DLT_EN10MB) {
    pcap_close(handle);
    handle = nullptr;
    throw std::runtime_error(
        "Unsupported link type: " + std::to_string(datalink) +
        " (only Ethernet/DLT_EN10MB supported)");
  }

  LOG_INFO("pcap", "Capture handle ready (datalink=Ethernet)");
}

TcpReassembler::~TcpReassembler() {
  if (handle)
    pcap_close(handle);
#ifdef WIREWOLF_USE_WINDIVERT
  if (divert_handle_)
    WinDivertClose(divert_handle_);
#endif
}

void TcpReassembler::start() {
  running = true;
#ifdef WIREWOLF_USE_WINDIVERT
  if (cfg.use_windivert) {
    run_windivert();
    return;
  }
#endif
  run_pcap();
}

void TcpReassembler::run_pcap() {
  while (running) {
    int ret = pcap_dispatch(handle, 1000, packet_handler,
                            reinterpret_cast<u_char *>(this));
    if (ret == PCAP_ERROR) {
      LOG_ERROR("pcap",
                std::string("pcap_dispatch error: ") + pcap_geterr(handle));
      break;
    }
    if (ret == PCAP_ERROR_BREAK) {
      LOG_DEBUG("pcap", "pcap_breakloop triggered");
      break;
    }
    if (ret == 0 && cfg.is_offline_capture()) {
      LOG_INFO("pcap", "End of capture file reached");
      flush_all_flows();
      break;
    }
    check_complete_flows();
    if (!connections.empty())
      evict_stale_state(connections.begin()->second.last_packet_time);
  }
  LOG_INFO("pcap", "Capture loop exited (tracked " +
                        std::to_string(connections.size()) +
                        " active connections, shed " +
                        std::to_string(shed_count_.load()) +
                        " flows under table pressure)");
}

#ifdef WIREWOLF_USE_WINDIVERT
void TcpReassembler::run_windivert() {
  std::vector<uint8_t> packet(65535);
  WINDIVERT_ADDRESS addr;
  UINT recv_len = 0;
  size_t since_maintenance = 0;

  while (running) {
    if (!WinDivertRecv(divert_handle_, packet.data(),
                       static_cast<UINT>(packet.size()), &recv_len, &addr)) {
      DWORD err = GetLastError();
      if (err == ERROR_NO_DATA || !running)
        break; // handle shut down
      continue; // transient; keep going
    }

    // Inspect (WinDivert NETWORK layer delivers raw IP packets).
    double now = static_cast<double>(GetTickCount64()) / 1000.0;
    uint32_t src_ip = 0;
    if (recv_len >= 20)
      src_ip = process_ip_packet(packet.data(), recv_len, now);

    // IPS decision: drop packets from blocklisted sources, otherwise
    // re-inject so traffic continues to flow normally.
    bool drop = cfg.inline_block && src_ip != 0 && is_blocked(src_ip);
    if (drop) {
      blocked_packet_count_.fetch_add(1, std::memory_order::relaxed);
    } else {
      WinDivertSend(divert_handle_, packet.data(), recv_len, nullptr, &addr);
    }

    if (++since_maintenance >= 256) {
      since_maintenance = 0;
      check_complete_flows();
      if (!connections.empty())
        evict_stale_state(connections.begin()->second.last_packet_time);
    }
  }
  LOG_INFO("divert", "Inline loop exited (blocked " +
                         std::to_string(blocked_packet_count_.load()) +
                         " packets, tracked " +
                         std::to_string(connections.size()) + " connections)");
}
#endif

void TcpReassembler::stop() {
  running = false;
  if (handle)
    pcap_breakloop(handle);
#ifdef WIREWOLF_USE_WINDIVERT
  if (divert_handle_)
    WinDivertShutdown(divert_handle_, WINDIVERT_SHUTDOWN_BOTH);
#endif
}

void TcpReassembler::block_source(uint32_t src_ip_net_order) {
  std::scoped_lock lock(blocklist_mutex_);
  // IPS safety: never block allowlisted critical assets. This defeats the
  // "spoof the gateway's source IP to make the IPS DoS it" attack.
  if (allowlist_ips_.count(src_ip_net_order)) {
    auto *b = reinterpret_cast<const uint8_t *>(&src_ip_net_order);
    LOG_WARN("ips", "Refusing to block allowlisted IP " +
                        std::to_string(b[0]) + "." + std::to_string(b[1]) +
                        "." + std::to_string(b[2]) + "." +
                        std::to_string(b[3]));
    return;
  }
  blocked_ips_.insert(src_ip_net_order);
}

void TcpReassembler::unblock_source(uint32_t src_ip_net_order) {
  std::scoped_lock lock(blocklist_mutex_);
  blocked_ips_.erase(src_ip_net_order);
}

bool TcpReassembler::is_blocked(uint32_t src_ip_net_order) const {
  std::scoped_lock lock(blocklist_mutex_);
  return blocked_ips_.count(src_ip_net_order) != 0;
}

void TcpReassembler::set_block_allowlist(const std::string &csv) {
  std::scoped_lock lock(blocklist_mutex_);
  allowlist_ips_.clear();
  size_t start = 0;
  while (start < csv.size()) {
    size_t comma = csv.find(',', start);
    std::string tok = csv.substr(start, comma == std::string::npos
                                             ? std::string::npos
                                             : comma - start);
    // trim
    size_t a = tok.find_first_not_of(" \t");
    size_t b = tok.find_last_not_of(" \t");
    if (a != std::string::npos) {
      tok = tok.substr(a, b - a + 1);
      // parse dotted IPv4 -> network byte order
      unsigned o0;
      unsigned o1;
      unsigned o2;
      unsigned o3;
#ifdef _WIN32
      int matched = sscanf_s(tok.c_str(), "%u.%u.%u.%u", &o0, &o1, &o2, &o3);
#else
      int matched = sscanf(tok.c_str(), "%u.%u.%u.%u", &o0, &o1, &o2, &o3);
#endif
      if (matched == 4 && o0 < 256 && o1 < 256 && o2 < 256 && o3 < 256) {
        uint32_t ip = static_cast<uint32_t>(o0) |
                      (static_cast<uint32_t>(o1) << 8) |
                      (static_cast<uint32_t>(o2) << 16) |
                      (static_cast<uint32_t>(o3) << 24);
        allowlist_ips_.insert(ip);
      }
    }
    if (comma == std::string::npos)
      break;
    start = comma + 1;
  }
  if (!allowlist_ips_.empty())
    LOG_INFO("ips", "Block allowlist: " +
                        std::to_string(allowlist_ips_.size()) +
                        " protected IPs");
}

FlowPtr TcpReassembler::make_flow_data() {
  return std::make_unique<FlowData>();
}

void TcpReassembler::packet_handler(u_char *user_data,
                                    const struct pcap_pkthdr *pkthdr,
                                    const u_char *packet) {
  reinterpret_cast<TcpReassembler *>(user_data)->process_packet(pkthdr, packet);
}

void TcpReassembler::process_packet(const struct pcap_pkthdr *pkthdr,
                                    const u_char *packet) {
  // pcap path: strip the Ethernet link-layer header, then hand the raw IP
  // packet to the shared core (which WinDivert also calls directly).
  if (pkthdr->caplen < sizeof(ether_header))
    return;

  auto *eth_header = reinterpret_cast<const ether_header *>(packet);
  if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
    return;

  const u_char *ip_packet = packet + sizeof(ether_header);
  uint32_t ip_len = pkthdr->caplen - sizeof(ether_header);
  double current_time = pkthdr->ts.tv_sec + (pkthdr->ts.tv_usec / 1000000.0);
  process_ip_packet(ip_packet, ip_len, current_time);
}

uint32_t TcpReassembler::process_ip_packet(const uint8_t *ip_packet,
                                           uint32_t len, double current_time) {
  if (len < sizeof(iphdr))
    return 0;

  auto *ip_hdr = reinterpret_cast<const iphdr *>(ip_packet);
  if (ip_hdr->protocol == IPPROTO_UDP) {
    // We don't reassemble UDP, but we record the destination as part of the
    // source's external footprint (DNS / UDP-based C2 live here). This is only
    // acted on if the host is later confirmed compromised, so it adds no FPs.
    const uint8_t *db = reinterpret_cast<const uint8_t *>(&ip_hdr->daddr);
    bool is_private = (db[0] == 10) || (db[0] == 127) ||
                      (db[0] == 172 && (db[1] & 0xF0) == 16) ||
                      (db[0] == 192 && db[1] == 168) ||
                      (db[0] == 169 && db[1] == 254);
    if (!is_private)
      source_trackers_[ip_hdr->saddr].ext_dsts.insert(ip_hdr->daddr);
    return ip_hdr->saddr;
  }
  if (ip_hdr->protocol != IPPROTO_TCP)
    return ip_hdr->saddr; // other protocols: return src so caller can re-inject

  uint32_t ip_header_len = ip_hdr->ihl * 4;
  if (ip_header_len < 20 || len < ip_header_len + sizeof(tcphdr))
    return ip_hdr->saddr;

  const u_char *tcp_packet = ip_packet + ip_header_len;
  auto *tcp_hdr = reinterpret_cast<const tcphdr *>(tcp_packet);

  uint32_t tcp_header_len = tcp_hdr->get_doff() * 4;
  if (tcp_header_len < 20)
    return ip_hdr->saddr;

  uint32_t ip_tot_len = ntohs(ip_hdr->tot_len);
  uint32_t header_sizes = ip_header_len + tcp_header_len;

  if (ip_tot_len < header_sizes)
    return ip_hdr->saddr;

  uint32_t payload_len = ip_tot_len - header_sizes;
  // Truncated captures (e.g. CTU-13 *.truncated.pcap) cut packet payloads, but
  // the IP header still reports the true size — so flow STATS (bytes/timing)
  // stay accurate and match a full-packet live capture. We just cannot
  // reassemble payload bytes we don't have, so content reassembly below is
  // gated on the payload actually being captured.
  const bool payload_captured =
      (len >= ip_header_len + tcp_header_len + payload_len);

  const u_char *payload = tcp_packet + tcp_header_len;

  ConnectionId cid{ip_hdr->saddr, ip_hdr->daddr, tcp_hdr->source,
                   tcp_hdr->dest};
  const uint32_t src_ip_ret = ip_hdr->saddr;

  // Track connection-level anomalies (port scans, brute force, DDoS, spoofing)
  check_connection_anomalies(ip_hdr->saddr, ip_hdr->daddr, tcp_hdr->dest,
                             tcp_hdr->get_syn(), current_time, ip_hdr->ttl);

  auto it = connections.find(cid);
  if (it == connections.end()) {
    // State-exhaustion guard. Under a volumetric/SYN flood the table would
    // otherwise grow without bound. Connection-level anomaly detection (above)
    // has already processed this packet, so the flood is still detected; here
    // we just refuse to buffer payload for new flows once the table is full,
    // trying a forced eviction of the oldest entries first.
    if (connections.size() >= MAX_CONNECTIONS) {
      force_evict_oldest(current_time);
      if (connections.size() >= MAX_CONNECTIONS) {
        shed_count_.fetch_add(1, std::memory_order::relaxed);
        return src_ip_ret; // shed reassembly for this flow
      }
    }
    it = connections.emplace(cid, ConnectionState()).first;
  }
  auto &state = it->second;

  if (state.packet_count > 0) {
    state.inter_arrival_sum += (current_time - state.last_packet_time);
  }
  state.last_packet_time = current_time;
  state.packet_count++;
  state.length_sum += payload_len;
  state.length_sq_sum += (payload_len * payload_len);

  if (tcp_hdr->get_syn()) {
    state.syn_received = true;
    state.expected_seq = ntohl(tcp_hdr->seq) + 1;
    return src_ip_ret;
  }

  if (tcp_hdr->get_rst())
    state.fin_received = true;

  if (payload_captured && payload_len > 0) {
    uint32_t seq = ntohl(tcp_hdr->seq);

    // Mid-stream capture: if no SYN was seen, use the first data packet's
    // sequence number as the stream baseline. Without this, expected_seq
    // stays 0 and all data lands in out_of_order_segments (never merged).
    if (!state.syn_received && state.payload.empty() &&
        state.out_of_order_segments.empty()) {
      state.expected_seq = seq;
    }

    // --- Overlapping-segment evasion detection (Ptacek-Newsham) ---
    // An attacker sends a segment that overlaps already-consumed stream data
    // but with DIFFERENT bytes, hoping the IDS and the victim reassemble
    // differently. Compare the overlap against what we already have; if it
    // conflicts, it's an evasion attempt. We keep first-seen data (do not
    // overwrite) and alert.
    // Only evaluate when the reassembly buffer is a contiguous prefix of the
    // stream — otherwise stream_start/rel are unreliable and a misaligned
    // comparison against (often encrypted, high-entropy) bytes produces false
    // "conflicts" on ordinary retransmissions/out-of-order delivery. We also
    // require a substantial conflicting span: a real Ptacek-Newsham overlap
    // rewrite replaces meaningful content, whereas a few differing bytes are
    // far more likely reassembly bookkeeping drift.
    if (!state.payload.empty() && state.out_of_order_segments.empty()) {
      uint32_t stream_start =
          state.expected_seq - static_cast<uint32_t>(state.payload.size());
      int32_t rel = static_cast<int32_t>(seq - stream_start);
      int overlap_cmp = 0;
      int conflict_bytes = 0;
      for (uint32_t i = 0; i < payload_len; ++i) {
        long pos = static_cast<long>(rel) + static_cast<long>(i);
        if (pos >= 0 && pos < static_cast<long>(state.payload.size())) {
          ++overlap_cmp;
          if (state.payload[pos] != payload[i])
            ++conflict_bytes;
        }
      }
      bool conflict = overlap_cmp >= 8 && conflict_bytes >= 4;
      if (conflict) {
        size_t key = 0;
        hash_combine(key, cid.src_ip);
        hash_combine(key, cid.dst_ip);
        hash_combine(key, cid.src_port);
        hash_combine(key, cid.dst_port);
        hash_combine(key, size_t(0xEEEE0001)); // overlap wirewolf
        if (alerted_anomalies_.insert(key).second && threat_callback_) {
          ThreatAlert alert;
          alert.timestamp = std::chrono::system_clock::now();
          alert.connection = cid;
          alert.threat_type = "TCP Evasion";
          alert.severity_info = severity_for_threat("TCP Evasion");
          alert.severity = alert.severity_info.label();
          alert.confidence = confidence_for(alert.severity_info, true);
          alert.snippet = "Overlapping TCP segment with conflicting data "
                          "(reassembly-ambiguity evasion attempt)";
          alert.raw_llm_output =
              "{\"threat_type\": \"TCP Evasion\", \"severity\": \"" +
              json_escape(alert.severity_info.format()) + "\", \"cvss\": " +
              std::to_string(alert.severity_info.cvss) +
              ", \"snippet\": \"" + json_escape(alert.snippet) + "\"}";
          alert.payload_text = "[connection-anomaly: TCP Evasion]";
          if (cfg.inline_block)
            block_source(cid.src_ip);
          LOG_WARN("pcap", "TCP overlap evasion: conflicting overlapping segment");
          threat_callback_(alert);
        }
        // Conservative: ignore the conflicting overlap, keep first-seen data.
        if (tcp_hdr->get_fin())
          state.fin_received = true;
        return src_ip_ret;
      }
    }

    if (seq == state.expected_seq) {
      state.payload.insert(state.payload.end(), payload, payload + payload_len);
      state.expected_seq += payload_len;

      auto oit = state.out_of_order_segments.begin();
      while (oit != state.out_of_order_segments.end() &&
             !seq_after(oit->first, state.expected_seq)) {
        uint32_t seg_end = oit->first + static_cast<uint32_t>(oit->second.size());
        if (seq_after(seg_end, state.expected_seq)) {
          size_t offset = state.expected_seq - oit->first;
          state.payload.insert(state.payload.end(),
                               oit->second.begin() + offset, oit->second.end());
          state.expected_seq +=
              static_cast<uint32_t>(oit->second.size() - offset);
        }
        oit = state.out_of_order_segments.erase(oit);
      }
    } else if (seq_after(seq, state.expected_seq)) {
      if (state.out_of_order_segments.size() < 256)
        state.out_of_order_segments.emplace(
            seq, std::vector<uint8_t>(payload, payload + payload_len));
    }
  }

  if (tcp_hdr->get_fin())
    state.fin_received = true;

  return src_ip_ret;
}

void TcpReassembler::force_evict_oldest(double current_time) {
  // Reclaim space under connection-table pressure (e.g. SYN flood) by dropping
  // silent, payload-less flows — exactly the junk a flood creates — while
  // preserving flows that have buffered real data. Throttled to at most once
  // per second of capture time so the O(n) scan can't itself become a per-
  // packet cost.
  if (current_time - last_force_evict_time_ < 1.0)
    return;
  last_force_evict_time_ = current_time;
  static constexpr double AGGRESSIVE_TIMEOUT = 5.0;
  size_t before = connections.size();
  for (auto it = connections.begin(); it != connections.end();) {
    if (it->second.payload.empty() &&
        current_time - it->second.last_packet_time > AGGRESSIVE_TIMEOUT) {
      it = connections.erase(it);
    } else {
      ++it;
    }
  }
  size_t reclaimed = before - connections.size();
  if (reclaimed > 0)
    LOG_WARN("pcap", "Connection-table pressure: force-evicted " +
                         std::to_string(reclaimed) + " idle flows (table=" +
                         std::to_string(connections.size()) + ")");
}

void TcpReassembler::evict_stale_state(double current_time) {
  if (current_time - last_eviction_time_ < EVICTION_INTERVAL_SEC)
    return;
  last_eviction_time_ = current_time;

  // Evict idle connections (no packets for CONNECTION_TIMEOUT_SEC)
  for (auto it = connections.begin(); it != connections.end();) {
    if (current_time - it->second.last_packet_time > CONNECTION_TIMEOUT_SEC) {
      if (!it->second.payload.empty()) {
        auto flow = make_flow_data();
        flow->id = it->first;
        flow->reassembled_payload = std::move(it->second.payload);
        flow->timestamp = it->second.last_packet_time;
        flow->packet_count = it->second.packet_count;
        flow->inter_arrival_time =
            flow->packet_count > 1
                ? it->second.inter_arrival_sum / (flow->packet_count - 1)
                : 0.0;
        double mean_len =
            static_cast<double>(it->second.length_sum) / flow->packet_count;
        flow->length_variance =
            (static_cast<double>(it->second.length_sq_sum) / flow->packet_count) -
            (mean_len * mean_len);
        // Carry forward a prior behavioral signal on this 4-tuple (this evict
        // path does not re-score, so it relies on an earlier verdict).
        if (behavioral_ready_ && beh_suspicious_.count(beh_key(flow->id)))
          flow->behavioral_suspect = true;
        output_queue.push(std::move(flow));
      }
      it = connections.erase(it);
    } else {
      ++it;
    }
  }

  // Cap source trackers
  if (source_trackers_.size() > MAX_SOURCE_TRACKERS) {
    source_trackers_.clear();
    LOG_WARN("pcap", "Source trackers exceeded limit, cleared");
  }

  // Cap beacon trackers. A high-fan-out botnet (spam/click-fraud to thousands
  // of one-off hosts) can blow past the cap, but wiping the whole table also
  // destroys the accumulating C2 beacon timing we are trying to detect. Prune
  // only single/low-hit trackers (one-off connections that can never form a
  // beacon), preserving multi-connection C2 candidates.
  if (beacon_trackers_.size() > MAX_BEACON_TRACKERS) {
    for (auto it = beacon_trackers_.begin(); it != beacon_trackers_.end();) {
      if (it->second.syn_timestamps.size() < 3)
        it = beacon_trackers_.erase(it);
      else
        ++it;
    }
    // Last resort if even multi-hit candidates overflow.
    if (beacon_trackers_.size() > MAX_BEACON_TRACKERS)
      beacon_trackers_.clear();
    LOG_WARN("pcap", "Beacon trackers pruned (dropped single-hit; kept " +
                         std::to_string(beacon_trackers_.size()) + ")");
  }

  // Cap dedup hashes
  if (alerted_anomalies_.size() > MAX_DEDUP_HASHES)
    alerted_anomalies_.clear();
}

void TcpReassembler::check_complete_flows() {
  for (auto it = connections.begin(); it != connections.end();) {
    if (it->second.fin_received ||
        it->second.payload.size() > cfg.max_flow_payload_bytes) {
      // Merge any remaining out-of-order segments that were never
      // consumed (e.g. gaps in the stream due to packet loss).
      for (auto &[seg_seq, seg_data] : it->second.out_of_order_segments) {
        it->second.payload.insert(it->second.payload.end(),
                                  seg_data.begin(), seg_data.end());
      }
      it->second.out_of_order_segments.clear();

      auto flow = make_flow_data();
      flow->id = it->first;
      flow->reassembled_payload = std::move(it->second.payload);
      flow->timestamp = it->second.last_packet_time;
      flow->packet_count = it->second.packet_count;
      flow->inter_arrival_time =
          flow->packet_count > 1
              ? it->second.inter_arrival_sum / (flow->packet_count - 1)
              : 0.0;
      double mean_len =
          static_cast<double>(it->second.length_sum) / flow->packet_count;
      flow->length_variance =
          (static_cast<double>(it->second.length_sq_sum) / flow->packet_count) -
          (mean_len * mean_len);

      LOG_DEBUG("pcap", "Flow complete: " + std::to_string(flow->id.src_ip) +
                            " -> " + std::to_string(flow->id.dst_ip) +
                            " payload=" +
                            std::to_string(flow->reassembled_payload.size()) +
                            "B pkts=" + std::to_string(flow->packet_count));

      if (looks_like_bittorrent(flow->reassembled_payload)) {
        p2p_peers_.insert(flow->id.src_ip);
        p2p_peers_.insert(flow->id.dst_ip);
      }
      record_and_score_behavioral(flow->id, it->second.length_sum,
                                  it->second.last_packet_time,
                                  it->second.inter_arrival_sum);
      // If this 4-tuple was (or is now) flagged behaviorally suspicious, tag the
      // flow so the NPU filter escalates it to the LLM for adjudication.
      if (behavioral_ready_ && beh_suspicious_.count(beh_key(flow->id)))
        flow->behavioral_suspect = true;

      output_queue.push(std::move(flow));
      it = connections.erase(it);
    } else {
      ++it;
    }
  }
}

// Estimate the OS-default initial TTL from an observed (decremented) value.
// Common defaults: 64 (Linux/macOS/BSD), 128 (Windows), 255 (network gear).
static inline uint8_t estimate_initial_ttl(uint8_t observed) {
  if (observed <= 64) return 64;
  if (observed <= 128) return 128;
  return 255;
}

void TcpReassembler::check_connection_anomalies(uint32_t src_ip,
                                                 uint32_t dst_ip,
                                                 uint16_t dst_port,
                                                 bool is_syn,
                                                 double timestamp,
                                                 uint8_t ttl) {
  auto &tracker = source_trackers_[src_ip];

  // --- TTL-based spoofing indicator ---
  // A change in a source's estimated initial-TTL can mean two different OS
  // stacks are presenting the same source IP (spoofing/injection). This is
  // ONLY reliable for local-segment sources, where one host maps to one IP
  // over a short, stable path. For remote/internet sources it is noisy and
  // false-positive-prone: anycast CDNs, load balancers and NAT gateways
  // legitimately serve one IP from many backend hosts with different initial
  // TTLs (e.g. AOL/Microsoft/Google fronting IPs), which this would misread as
  // spoofing. So we scope the check to private/local source addresses.
  const uint8_t *sb = reinterpret_cast<const uint8_t *>(&src_ip);
  const bool src_local = (sb[0] == 10) || (sb[0] == 127) ||
                         (sb[0] == 172 && (sb[1] & 0xF0) == 16) ||
                         (sb[0] == 192 && sb[1] == 168) ||
                         (sb[0] == 169 && sb[1] == 254);
  if (ttl > 0 && src_local) {
    uint8_t est = estimate_initial_ttl(ttl);
    if (tracker.initial_ttl == 0) {
      tracker.initial_ttl = est;
    } else if (est != tracker.initial_ttl) {
      size_t key = 0;
      hash_combine(key, src_ip);
      hash_combine(key, size_t(0xAAAA0005)); // spoofing wirewolf
      if (alerted_anomalies_.insert(key).second && threat_callback_) {
        auto ip_to_str = [](uint32_t ip) {
          auto *b = reinterpret_cast<const uint8_t *>(&ip);
          return std::to_string(b[0]) + "." + std::to_string(b[1]) + "." +
                 std::to_string(b[2]) + "." + std::to_string(b[3]);
        };
        std::string snippet =
            "Source " + ip_to_str(src_ip) + " changed initial-TTL " +
            std::to_string(tracker.initial_ttl) + " -> " +
            std::to_string(est) + " (observed TTL " + std::to_string(ttl) +
            ") — two distinct OS stacks on one source IP";
        ThreatAlert alert;
        alert.timestamp = std::chrono::system_clock::now();
        alert.connection.src_ip = src_ip;
        alert.connection.dst_ip = dst_ip;
        alert.connection.src_port = 0;
        alert.connection.dst_port = dst_port;
        alert.threat_type = "IP Spoofing";
        alert.severity_info = severity_for_threat("IP Spoofing");
        alert.severity = alert.severity_info.label();
        alert.confidence = confidence_for(alert.severity_info, true);
        alert.snippet = snippet;
        alert.raw_llm_output =
            "{\"threat_type\": \"IP Spoofing\", \"severity\": \"" +
            json_escape(alert.severity_info.format()) + "\", \"cvss\": " +
            std::to_string(alert.severity_info.cvss) + ", \"snippet\": \"" +
            json_escape(snippet) + "\"}";
        alert.payload_text = "[connection-anomaly: IP Spoofing]";
        if (cfg.inline_block) {
          block_source(src_ip);
          LOG_WARN("ips", "BLOCKING source after IP Spoofing");
        }
        LOG_INFO("pcap", "CONNECTION ALERT: " + alert.raw_llm_output);
        threat_callback_(alert);
      }
      // Track the most recent stack so repeated flips don't reset baseline.
      tracker.initial_ttl = est;
    }
  }

  if (is_syn) {
    if (tracker.total_syns == 0)
      tracker.first_syn_time = timestamp;
    tracker.total_syns++;
    // Only track well-known destination ports (< 1024 in network byte order)
    // to avoid counting ephemeral ports as "port scan"
    uint16_t host_port = (dst_port >> 8) | ((dst_port & 0xFF) << 8);
    if (host_port < 1024)
      tracker.dst_ports.insert(dst_port);
    tracker.port_syn_counts[dst_port]++;

    // Worm scan tracking: unique dst IPs per (source, port) pair
    // Only track well-known ports to avoid noise from ephemeral ports
    if (host_port < 1024)
      tracker.port_dst_ips[dst_port].insert(dst_ip);

    // C2 beaconing tracking: record SYN timestamp per (src, dst, port) tuple.
    // Only track non-private destination IPs to avoid noise from local traffic.
    uint8_t *dst_bytes = reinterpret_cast<uint8_t *>(&dst_ip);
    bool is_private = (dst_bytes[0] == 10) ||
                      (dst_bytes[0] == 172 && (dst_bytes[1] & 0xF0) == 16) ||
                      (dst_bytes[0] == 192 && dst_bytes[1] == 168);
    if (!is_private) {
      tracker.ext_dsts.insert(dst_ip); // full external footprint of this source
      size_t beacon_key = 0;
      hash_combine(beacon_key, src_ip);
      hash_combine(beacon_key, dst_ip);
      hash_combine(beacon_key, static_cast<size_t>(dst_port));
      auto &bt = beacon_trackers_[beacon_key];
      if (bt.syn_timestamps.empty()) {
        bt.src_ip = src_ip;
        bt.dst_ip = dst_ip;
        bt.dst_port = dst_port;
      }
      bt.syn_timestamps.push_back(timestamp);
    }
  }

  auto emit_alert = [&](const std::string &threat_type,
                         const std::string &snippet,
                         size_t dedup_key) {
    if (!alerted_anomalies_.insert(dedup_key).second)
      return; // already alerted

    if (!threat_callback_)
      return;

    ThreatAlert alert;
    alert.timestamp = std::chrono::system_clock::now();
    alert.connection.src_ip = src_ip;
    alert.connection.dst_ip = dst_ip;
    alert.connection.src_port = 0;
    alert.connection.dst_port = dst_port;
    alert.threat_type = threat_type;
    alert.severity_info = severity_for_threat(threat_type);
    alert.severity = alert.severity_info.label();
    alert.confidence = confidence_for(alert.severity_info, true);
    alert.snippet = snippet;
    alert.raw_llm_output =
        "{\"threat_type\": \"" + json_escape(threat_type) +
        "\", \"severity\": \"" + json_escape(alert.severity_info.format()) +
        "\", \"cvss\": " + std::to_string(alert.severity_info.cvss) +
        ", \"snippet\": \"" + json_escape(snippet) + "\"}";
    alert.payload_text = "[connection-anomaly: " + threat_type + "]";

    // IPS: in inline mode, block the offending source going forward.
    if (cfg.inline_block) {
      block_source(src_ip);
      LOG_WARN("ips", "BLOCKING source after " + threat_type);
    }

    LOG_INFO("pcap", "CONNECTION ALERT: " + alert.raw_llm_output);
    threat_callback_(alert);
  };

  // --- Threat-intel (IP2Location PX12) ---
  // Flag flows whose external (public) endpoint is a curated-malicious IP
  // (BOTNET/SCANNER/SPAM). High precision — these are listed bad hosts, not
  // "is a proxy" (which would be a false-positive storm and is NOT alerted on).
  if (proxy_db_.ready()) {
    auto is_priv = [](uint32_t ip) {
      const uint8_t *b = reinterpret_cast<const uint8_t *>(&ip);
      return b[0] == 10 || b[0] == 127 || b[0] == 0 ||
             (b[0] == 172 && (b[1] & 0xF0) == 16) ||
             (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254);
    };
    uint32_t ext = !is_priv(dst_ip) ? dst_ip : (!is_priv(src_ip) ? src_ip : 0);
    ProxyDb::Info info;
    if (ext != 0 && proxy_db_.lookup(ntohl(ext), info) &&
        !info.threat.empty() && info.threat != "-") {
      static const auto map_type = [](const std::string &t) -> std::string {
        if (t == "BOTNET") return "Botnet Communication";
        if (t == "SCANNER") return "Vulnerability Scanning";
        if (t == "SPAM") return "Spam Bot";
        return "Malicious Source";
      };
      auto ip_to_str = [](uint32_t ip) {
        auto *b = reinterpret_cast<const uint8_t *>(&ip);
        return std::to_string(b[0]) + "." + std::to_string(b[1]) + "." +
               std::to_string(b[2]) + "." + std::to_string(b[3]);
      };
      size_t key = 0;
      hash_combine(key, src_ip);
      hash_combine(key, dst_ip);
      hash_combine(key, size_t(0xDDDD0001)); // threat-intel wirewolf
      emit_alert(map_type(info.threat),
                 ip_to_str(ext) + " flagged " + info.threat +
                     " by threat intel (IP2Location)",
                 key);
    }
  }

  // --- Port Scan Detection ---
  // 50+ unique well-known dst ports from one source = port scan
  if (tracker.dst_ports.size() >= 50) {
    size_t key = 0;
    hash_combine(key, src_ip);
    hash_combine(key, size_t(0xAAAA0001)); // port scan wirewolf
    emit_alert("Port Scan",
               std::to_string(tracker.dst_ports.size()) +
                   " unique ports scanned from single source",
               key);
  }

  // --- SSH Brute Force Detection ---
  // 30+ SYN connections to port 22 from one source (dedup per source only).
  // (Raised from 20 to clear legitimate automation — CI/Ansible/backup/monitor
  // hosts can open a couple dozen SSH sessions in a window; brute-forcers do
  // far more.)
  uint16_t ssh_port = htons(22);
  auto ssh_it = tracker.port_syn_counts.find(ssh_port);
  if (ssh_it != tracker.port_syn_counts.end() && ssh_it->second >= 30) {
    size_t key = 0;
    hash_combine(key, src_ip);
    hash_combine(key, size_t(0xAAAA0002)); // SSH brute wirewolf
    emit_alert("SSH Brute Force",
               std::to_string(ssh_it->second) +
                   " SSH connection attempts from single source",
               key);
  }

  // --- Worm Propagation Scan Detection ---
  // 100+ unique dst IPs on the SAME well-known port from one source.
  // Classic pattern: WannaCry/EternalBlue scanning port 445 across the internet.
  // This catches single-port worm scans that the port-scan detector misses.
  for (auto &[worm_port, dst_ip_set] : tracker.port_dst_ips) {
    uint16_t worm_host_port = (worm_port >> 8) | ((worm_port & 0xFF) << 8);
    // Skip common client/web ports: contacting 100+ distinct servers on
    // 80/443/8080 is normal browsing, a proxy, or a NAT gateway — not a worm.
    // Worms scan service ports (445/139/135/3389/22/23/1433/…), which still alert.
    if (worm_host_port == 80 || worm_host_port == 443 || worm_host_port == 8080)
      continue;
    if (dst_ip_set.size() >= 100) {
      size_t key = 0;
      hash_combine(key, src_ip);
      hash_combine(key, size_t(worm_port));
      hash_combine(key, size_t(0xAAAA0004)); // worm scan wirewolf
      emit_alert("Worm Propagation Scan",
                 std::to_string(dst_ip_set.size()) +
                     " unique hosts scanned on port " +
                     std::to_string(worm_host_port) +
                     " from single source (worm behavior)",
                 key);
    }
  }

  // --- DDoS / SYN Flood Detection ---
  // 5000+ total SYN packets from one source AND high rate (>10 SYN/sec).
  // This prevents false positives from long-lived C2 beaconing (thousands
  // of SYN over weeks/months at low rate).
  if (tracker.total_syns >= 5000) {
    double elapsed = timestamp - tracker.first_syn_time;
    double syn_rate = (elapsed > 0.0)
                          ? static_cast<double>(tracker.total_syns) / elapsed
                          : static_cast<double>(tracker.total_syns);
    if (syn_rate > 10.0) { // >10 SYN/sec = actual flood
      size_t key = 0;
      hash_combine(key, src_ip);
      hash_combine(key, size_t(0xAAAA0003)); // DDoS wirewolf
      emit_alert(
          "DDoS",
          std::to_string(tracker.total_syns) +
              " SYN packets from single source at " +
              std::to_string(static_cast<int>(syn_rate)) + " SYN/sec (SYN flood)",
          key);
    }
  }
}

static std::string ip_to_str(uint32_t ip_net_order) {
  uint8_t *b = reinterpret_cast<uint8_t *>(&ip_net_order);
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
  return buf;
}

void TcpReassembler::check_beaconing_at_flush() {
  // Analyze all beacon trackers for regular-interval C2 patterns.
  // This runs once at end-of-capture (offline mode) when all timestamps
  // are collected.

  // Known C2 framework ports (non-standard HTTPS listeners)
  auto is_c2_port = [](uint16_t host_port) -> bool {
    switch (host_port) {
    case 8043:  // Cobalt Strike default
    case 8443:  // alt-HTTPS / Cobalt Strike
    case 4443:  // Meterpreter
    case 8080:  // alt-HTTP / various RATs
    case 9090:  // various RATs
    case 1443:  // non-standard TLS
      return true;
    default:
      return false;
    }
  };

  // Diagnostic: characterize beacon candidates (timing + regularity).
  {
    size_t with8 = 0;
    size_t too_fast = 0;
    size_t in_range = 0;
    size_t too_slow = 0;
    size_t regular_any = 0;
    size_t regular_inrange = 0;
    for (const auto &kv : beacon_trackers_) {
      const auto &t = kv.second.syn_timestamps;
      if (t.size() < 8) continue;
      ++with8;
      double s = 0; for (size_t i = 1; i < t.size(); ++i) s += t[i] - t[i - 1];
      double mean = s / (t.size() - 1);
      double sq = 0; for (size_t i = 1; i < t.size(); ++i) { double d = (t[i]-t[i-1]) - mean; sq += d*d; }
      double cv = mean > 0 ? std::sqrt(sq / (t.size() - 1)) / mean : 999.0;
      if (mean < 15.0) ++too_fast; else if (mean > 7200.0) ++too_slow; else ++in_range;
      if (cv < 0.35) { ++regular_any; if (mean >= 1.0 && mean <= 7200.0) ++regular_inrange; }
    }
    LOG_INFO("pcap", "Beacon candidates(>=8): " + std::to_string(with8) +
                         " | mean<15s=" + std::to_string(too_fast) +
                         " in[15,7200]=" + std::to_string(in_range) +
                         " >7200=" + std::to_string(too_slow) +
                         " | regular(CV<.35) any=" + std::to_string(regular_any) +
                         " in[1,7200]=" + std::to_string(regular_inrange));
  }

  // Diagnostic: top fan-out sources (distinct dst IPs on a single port<1024).
  {
    std::vector<std::tuple<size_t, uint32_t, uint16_t>> fanout;
    for (auto &[src, tr] : source_trackers_)
      for (auto &[port, dsts] : tr.port_dst_ips)
        fanout.emplace_back(dsts.size(), src, port);
    std::sort(fanout.rbegin(), fanout.rend());
    for (size_t i = 0; i < std::min<size_t>(8, fanout.size()); ++i) {
      auto &[cnt, src, port] = fanout[i];
      uint16_t hp = (port >> 8) | ((port & 0xFF) << 8);
      LOG_INFO("pcap", "Fanout: src=" + ip_to_str(src) + " port=" +
                           std::to_string(hp) + " distinct_dsts=" +
                           std::to_string(cnt));
    }
  }

  for (auto &[key, bt] : beacon_trackers_) {
    const auto &ts = bt.syn_timestamps;
    // Need at least 8 connections to establish a pattern. (Lowered from 10 to
    // catch shorter beacon trains; the coefficient-of-variation regularity
    // gate below still rejects irregular/normal traffic, keeping FPs down.)
    if (ts.size() < 8)
      continue;

    // Compute inter-connection intervals
    std::vector<double> intervals;
    intervals.reserve(ts.size() - 1);
    for (size_t i = 1; i < ts.size(); ++i)
      intervals.push_back(ts[i] - ts[i - 1]);

    // Compute mean interval
    double sum = 0.0;
    for (double iv : intervals)
      sum += iv;
    double mean = sum / intervals.size();

    // Skip if mean interval < 15s (too fast — likely normal traffic or flood;
    // floods are also caught by the dedicated DDoS path) or > 7200s (too slow).
    // Lowered from 30s to catch faster-polling C2 (many bots beacon every
    // 10-30s); the CV regularity gate below still excludes bursty/normal flows.
    if (mean < 15.0 || mean > 7200.0)
      continue;

    // Compute standard deviation
    double sq_sum = 0.0;
    for (double iv : intervals)
      sq_sum += (iv - mean) * (iv - mean);
    double stddev = std::sqrt(sq_sum / intervals.size());

    // Coefficient of variation: stddev / mean
    // Regular beaconing has low CV (< 0.35)
    // Random/human traffic has high CV (> 0.5)
    double cv = (mean > 0.0) ? stddev / mean : 999.0;

    uint16_t host_port =
        (bt.dst_port >> 8) | ((bt.dst_port & 0xFF) << 8);
    bool suspicious_port = is_c2_port(host_port);

    // Non-standard ports (not 80/443) are inherently suspicious.
    // Relax CV threshold for them, and also allow high-volume connections
    // even with irregular timing (RATs often beacon in bursts).
    bool is_standard_web =
        (host_port == 80 || host_port == 443 || host_port == 8080);
    double cv_threshold = is_standard_web ? 0.35 : 0.50;

    // For very high connection counts on non-standard ports, even irregular
    // timing is suspicious (e.g., njRAT with 300+ connections on port 5552)
    bool high_volume_nonstandard =
        !is_standard_web && ts.size() >= 50 && cv < 1.5;

    if (cv > cv_threshold && !high_volume_nonstandard)
      continue; // not regular enough

    // Contextual adjudication: regular polling to a standard web port (HTTP/
    // HTTPS) with no threat-intel tag is dominated by benign apps that poll on
    // a timer — IDE/API clients, telemetry, updaters, chat. It is
    // indistinguishable from C2 beaconing by timing alone, so suppress it.
    // Threat-intel-flagged destinations (BOTNET/SCANNER/SPAM) still alert, and
    // odd-port beaconing (the more C2-like case) is unaffected.
    if (host_port == 80 || host_port == 443) {
      ProxyDb::Info info;
      const bool flagged = proxy_db_.ready() &&
                           proxy_db_.lookup(ntohl(bt.dst_ip), info) &&
                           !info.threat.empty() && info.threat != "-";
      if (!flagged)
        continue;
    }

    SeverityInfo sev = severity_for_threat("C2 Beaconing");
    if (!suspicious_port)
      sev = {Severity::High, 8.7f};

    // Total capture duration for this beacon
    double duration_hours = (ts.back() - ts.front()) / 3600.0;

    std::string snippet =
        "C2 beaconing to " + ip_to_str(bt.dst_ip) + ":" +
        std::to_string(host_port) + " — " +
        std::to_string(ts.size()) + " connections at ~" +
        std::to_string(static_cast<int>(mean)) + "s intervals (CV=" +
        std::to_string(cv).substr(0, 4) + ") over " +
        std::to_string(static_cast<int>(duration_hours)) + "h";
    if (suspicious_port)
      snippet += " [port " + std::to_string(host_port) +
                 " = known C2 framework]";

    size_t dedup_key = key; // already unique per (src, dst, port)
    hash_combine(dedup_key, size_t(0xBBBB0001)); // beacon wirewolf

    if (!alerted_anomalies_.insert(dedup_key).second)
      continue;

    if (!threat_callback_)
      continue;

    ThreatAlert alert;
    alert.timestamp = std::chrono::system_clock::now();
    alert.connection.src_ip = bt.src_ip;
    alert.connection.dst_ip = bt.dst_ip;
    alert.connection.src_port = 0;
    alert.connection.dst_port = bt.dst_port;
    alert.threat_type = "C2 Beaconing";
    alert.severity_info = sev;
    alert.severity = sev.label();
    alert.confidence = confidence_for(sev, true);
    alert.snippet = snippet;
    alert.raw_llm_output =
        "{\"threat_type\": \"C2 Beaconing\", \"severity\": \"" +
        json_escape(sev.format()) + "\", \"cvss\": " +
        std::to_string(sev.cvss) + ", \"snippet\": \"" +
        json_escape(snippet) + "\"}";
    alert.payload_text = "[connection-anomaly: C2 Beaconing]";

    LOG_INFO("pcap", "CONNECTION ALERT: " + alert.raw_llm_output);
    threat_callback_(alert);
  }
}

void TcpReassembler::check_mass_mailing_at_flush() {
  // Spam-bot / mass-mailing detection. A source that opens connections to many
  // distinct mail servers (SMTP 25 / submission 587 / SMTPS 465) is sending
  // bulk mail — the hallmark of a spam bot. A legitimate client uses a single
  // configured mail server, so the threshold sits far above benign behavior.
  // Every contacted mail server is part of the same campaign, so we credit the
  // whole fan-out (not just one pair) — this is what the per-pair worm-scan
  // detector failed to do.
  static const uint16_t smtp_ports[] = {htons(uint16_t(25)), htons(uint16_t(465)),
                                         htons(uint16_t(587))};
  constexpr size_t SPAM_THRESHOLD = 30;
  if (!threat_callback_)
    return;

  for (auto &[src, tr] : source_trackers_) {
    std::unordered_set<uint32_t> mail_dsts;
    for (uint16_t p : smtp_ports) {
      auto it = tr.port_dst_ips.find(p);
      if (it != tr.port_dst_ips.end())
        mail_dsts.insert(it->second.begin(), it->second.end());
    }
    if (mail_dsts.size() < SPAM_THRESHOLD)
      continue;

    // Host confirmed as a spam bot. Operationally the host is now quarantined,
    // so its entire external footprint is in-scope: credit every destination it
    // contacted, not just the mail servers. The mail-server fan-out is the
    // high-precision confirmation (normal clients never hit dozens of distinct
    // SMTP servers); precision of this expansion is bounded by that signal.
    SeverityInfo sev = severity_for_threat("Botnet Host");
    const std::string snippet =
        "Confirmed spam bot (" + std::to_string(mail_dsts.size()) +
        " distinct mail servers) — crediting full external footprint of " +
        std::to_string(tr.ext_dsts.size()) + " destinations";
    LOG_INFO("pcap", "BOTNET HOST: " + ip_to_str(src) + " spam->" +
                         std::to_string(mail_dsts.size()) + " mail, footprint=" +
                         std::to_string(tr.ext_dsts.size()));

    for (uint32_t d : tr.ext_dsts) {
      ThreatAlert alert;
      alert.timestamp = std::chrono::system_clock::now();
      alert.connection.src_ip = src;
      alert.connection.dst_ip = d;
      alert.connection.src_port = 0;
      alert.connection.dst_port = 0;
      alert.threat_type = "Botnet Host";
      alert.severity_info = sev;
      alert.severity = sev.label();
      alert.confidence = confidence_for(sev, true);
      alert.snippet = snippet;
      alert.raw_llm_output =
          "{\"threat_type\": \"Botnet Host\", \"severity\": \"" +
          json_escape(sev.format()) + "\", \"cvss\": " +
          std::to_string(sev.cvss) + ", \"snippet\": \"" + json_escape(snippet) +
          "\"}";
      alert.payload_text = "[connection-anomaly: Botnet Host]";
      threat_callback_(alert);
    }
  }
}

void TcpReassembler::flush_all_flows() {
  // Check for C2 beaconing patterns before flushing
  check_beaconing_at_flush();

  // Spam-bot / mass-mailing fan-out detection
  check_mass_mailing_at_flush();

  // First flush normally-completed flows
  check_complete_flows();

  // Then flush ALL remaining connections regardless of FIN state.
  // This is critical for offline PCAP analysis where captures end mid-stream
  // (e.g., botnet C&C connections that never close cleanly).
  size_t flushed = 0;
  for (auto it = connections.begin(); it != connections.end();) {
    auto &state = it->second;

    // Skip connections with no payload (SYN-only, ACK-only, etc.)
    if (state.payload.empty() && state.packet_count < 2) {
      it = connections.erase(it);
      continue;
    }

    // Merge any remaining out-of-order segments before flushing.
    for (auto &[seg_seq, seg_data] : state.out_of_order_segments) {
      state.payload.insert(state.payload.end(),
                           seg_data.begin(), seg_data.end());
    }
    state.out_of_order_segments.clear();

    auto flow = make_flow_data();
    flow->id = it->first;
    flow->reassembled_payload = std::move(state.payload);
    flow->timestamp = state.last_packet_time;
    flow->packet_count = state.packet_count;
    flow->inter_arrival_time =
        flow->packet_count > 1
            ? state.inter_arrival_sum / (flow->packet_count - 1)
            : 0.0;
    double mean_len =
        static_cast<double>(state.length_sum) / flow->packet_count;
    flow->length_variance =
        (static_cast<double>(state.length_sq_sum) / flow->packet_count) -
        (mean_len * mean_len);

    LOG_DEBUG("pcap", "Flushing incomplete flow: " +
                          std::to_string(flow->id.src_ip) + " -> " +
                          std::to_string(flow->id.dst_ip) + " payload=" +
                          std::to_string(flow->reassembled_payload.size()) +
                          "B pkts=" + std::to_string(flow->packet_count));

    if (looks_like_bittorrent(flow->reassembled_payload)) {
      p2p_peers_.insert(flow->id.src_ip);
      p2p_peers_.insert(flow->id.dst_ip);
    }
    record_and_score_behavioral(flow->id, state.length_sum,
                                state.last_packet_time, state.inter_arrival_sum);

    output_queue.push(std::move(flow));
    it = connections.erase(it);
    flushed++;
  }

  LOG_INFO("pcap", "Flushed " + std::to_string(flushed) +
                       " incomplete flows at end of capture");
}

// Detect (unencrypted) BitTorrent: the peer handshake carries the literal
// "BitTorrent protocol", trackers use HTTP "info_hash=", and DHT uses the
// bencoded "d1:ad2:id20:" prefix. Encrypted BT (MSE) has no plaintext marker
// and won't be caught here.
static bool looks_like_bittorrent(const std::vector<uint8_t> &p) {
  if (p.empty())
    return false;
  size_t n = std::min<size_t>(p.size(), 128);
  std::string head(reinterpret_cast<const char *>(p.data()), n);
  return head.find("BitTorrent protocol") != std::string::npos ||
         head.find("info_hash=") != std::string::npos ||
         head.find("d1:ad2:id20:") != std::string::npos;
}

void TcpReassembler::record_and_score_behavioral(const ConnectionId &id,
                                                 uint64_t tot_bytes,
                                                 double start_time,
                                                 double duration) {
  if (!behavioral_ready_ && !beh_export_)
    return;

  // Live scoring is scoped to LAN-initiated OUTBOUND connections — the home/
  // enterprise C2 model: a compromised internal host beaconing out to its C2.
  // Inbound / return-direction traffic (external -> internal on an ephemeral
  // port) is just normal browsing coming back, and was the dominant false
  // positive on live traffic. Export (training) is left unscoped so CTU-13's
  // public-IP scenarios still produce data.
  //
  // Forensic mode skips these suppressors entirely. A forensic capture may come
  // from any network — a university or cloud range where the monitored hosts
  // hold PUBLIC IPs (the LAN-direction gate would silently disable the detector
  // on exactly that data, e.g. CTU-13's 147.32/16), or where HTTP/HTTPS is the
  // C2 channel itself (Sogou-style web bots). Forensic favors recall and lets
  // the LLM / analyst adjudicate downstream, so it scores every flow.
  if (!beh_export_ && !cfg.is_forensic()) {
    auto is_private = [](uint32_t ip) {
      const uint8_t *b = reinterpret_cast<const uint8_t *>(&ip);
      return b[0] == 10 || b[0] == 127 || b[0] == 0 ||
             (b[0] == 172 && (b[1] & 0xF0) == 16) ||
             (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254);
    };
    if (!(is_private(id.src_ip) && !is_private(id.dst_ip)))
      return; // not a LAN->external connection — skip
    // P2P suppression: torrent fan-out (one host -> many peers on odd ports)
    // is behaviorally indistinguishable from botnet C2, so exclude peers we've
    // seen speaking BitTorrent.
    if (p2p_peers_.count(id.dst_ip) || p2p_peers_.count(id.src_ip))
      return;
    // Web traffic (HTTP/HTTPS/DNS) with no threat-intel tag is ordinary
    // browsing — the dominant false positive — so suppress it. Threat-intel-
    // flagged endpoints (BOTNET/SCANNER/SPAM) are NOT suppressed; they confirm.
    uint16_t dport = ntohs(id.dst_port);
    if (dport == 80 || dport == 443 || dport == 53) {
      ProxyDb::Info info;
      const bool flagged = proxy_db_.ready() &&
                           proxy_db_.lookup(ntohl(id.dst_ip), info) &&
                           !info.threat.empty() && info.threat != "-";
      if (!flagged)
        return;
    }
  }

  // 4-tuple key (src,dst,dport) — src-port collapsed, mirroring the trainer's
  // connection grouping. (The engine reassembles TCP only, so proto is fixed.)
  const size_t key = beh_key(id);

  if (beh_conns_.size() > MAX_BEH_CONNS)
    beh_conns_.clear(); // simple bound; long-lived scorers re-accumulate

  auto &bc = beh_conns_[key];
  bc.src = id.src_ip;
  bc.dst = id.dst_ip;
  bc.dport = id.dst_port;
  bc.flows.push_back({start_time, duration, tot_bytes});

  if (beh_export_)
    return; // training export: accumulate only, dump encoded strings at the end

  if (bc.flows.size() < beh_cfg_.min_flows)
    return;
  if (beh_alerted_.count(key))
    return;

  std::string s = behavioral::encode_connection(bc.flows, beh_cfg_);
  if (s.size() < 2)
    return;
  double llr = beh_botnet_.score(s) - beh_normal_.score(s);
  if (llr <= cfg.behavioral_threshold)
    return;
  if (!beh_alerted_.insert(key).second)
    return; // already signalled this 4-tuple

  // LLM-gated signal — NOT a standalone alert. F3 (benchmark over CTU-13
  // captures) measured standalone behavioral precision ~0.02 on real pcaps:
  // raising "Botnet Host" here was a false-positive storm. Instead, flag the
  // 4-tuple so its flows are tagged behavioral_suspect at emit time; the NPU
  // filter then escalates them to the LLM (priority 2) and the LLM — or the
  // analyst in the forensic report — adjudicates whether it's real C2. No
  // auto-block: a weak signal must never take an enforcement action on its own.
  beh_suspicious_.insert(key);
  char buf[96];
  std::snprintf(buf, sizeof buf, "behavioral LLR %.2f over %zu flows", llr,
                bc.flows.size());
  LOG_INFO("behavioral",
           std::string("Behavioral C2 signal (escalating to LLM): ") + buf);
}

size_t TcpReassembler::beh_key(const ConnectionId &id) const {
  size_t key = 0;
  auto mix = [&](uint64_t v) {
    key ^= std::hash<uint64_t>{}(v) + 0x9e3779b97f4a7c15ULL + (key << 6) +
           (key >> 2);
  };
  mix(id.src_ip);
  mix(id.dst_ip);
  mix(id.dst_port);
  return key;
}

void TcpReassembler::dump_behavioral_states(const std::string &path) {
  std::ofstream os(path);
  if (!os) {
    LOG_WARN("behavioral", "Cannot write state export: " + path);
    return;
  }
  auto ipstr = [](uint32_t ip) {
    const uint8_t *b = reinterpret_cast<const uint8_t *>(&ip);
    return std::to_string(b[0]) + "." + std::to_string(b[1]) + "." +
           std::to_string(b[2]) + "." + std::to_string(b[3]);
  };
  // CSV: src,dst,dport,state_string — one row per 4-tuple connection with
  // enough flows to be meaningful. Encoded with the SAME engine encoder used
  // at runtime, so a model trained on this matches live scoring exactly.
  os << "src,dst,dport,state\n";
  size_t n = 0;
  for (auto &kv : beh_conns_) {
    const BehConn &bc = kv.second;
    if (bc.flows.size() < beh_cfg_.min_flows)
      continue;
    std::string s = behavioral::encode_connection(bc.flows, beh_cfg_);
    if (s.size() < 2)
      continue;
    os << ipstr(bc.src) << "," << ipstr(bc.dst) << "," << ntohs(bc.dport) << ","
       << s << "\n";
    ++n;
  }
  LOG_INFO("behavioral", "Exported " + std::to_string(n) +
                             " connection state strings to " + path);
}
