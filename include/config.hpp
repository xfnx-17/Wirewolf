#pragma once
#include <cstddef>
#include <cstdint>
#include <string>

// Operating mode for the engine. The same pipeline runs in both modes; only
// how aggressively the LLM is used changes.
//   Live     = real-time NIDS. Fast detectors decide; a content-signature hit
//              is a deterministic verdict and skips the LLM (stay real-time).
//   Forensic = deep offline analysis of a .pcap. The LLM also arbitrates
//              signature hits for richer confirmation/explanation.
//   Auto     = Forensic when the input is a capture file, else Live.
// See obsidian-vault/architecture/"Operating Modes (Live NIDS vs Forensic).md"
enum class AnalysisMode { Auto, Live, Forensic };

struct WirewolfConfig {
  // Queue settings
  size_t queue_capacity = 1024;

  // TCP reassembly
  size_t max_flow_payload_bytes = 1048576; // 1 MB

  // NPU filter thresholds
  float entropy_high_threshold = 7.0f;   // Above = suspicious (encrypted/obfuscated)
  float entropy_low_threshold = 1.0f;    // Below with large payload = suspicious
  float variance_threshold = 50000.0f;   // High length variance = scanning/probing
  float inter_arrival_floor = 0.0005f;   // Very fast packets = flood
  size_t min_packet_count_for_flood = 50;
  size_t min_payload_for_low_entropy = 512;
  bool openvino_enabled = false; // Use statistical filter by default
  float npu_threshold = 0.5f;   // NPU model confidence threshold (higher = fewer flows to LLM)

  // LLM inference
  size_t payload_char_limit = 2048;
  int max_tokens = 512;
  // Forensic time bound: max flows actually run through the LLM (0 = unlimited).
  // Fast detectors still decide/emit beyond this; it just caps LLM spend so a
  // large capture finishes in bounded time instead of hours.
  size_t max_llm_flows = 0;
  // Must fit the detailed system prompt (~6k tokens) + few-shot examples + the
  // flow payload + the assistant header, within context_size minus max_tokens.
  // At 2000 the payload and assistant header were truncated away, leaving the
  // model to continue the system prompt instead of answering.
  int max_prompt_tokens = 7000;
  int n_gpu_layers = 99;
  uint32_t context_size = 8192;

  // Capture
  // Optional path to the preprocessed IP2Location PX12 proxy/threat binary
  // (proxy.bin; its .str sits beside it). When set, the engine flags flows
  // whose external endpoint is a curated-malicious IP (BOTNET/SCANNER/SPAM).
  std::string threat_proxy_db;

  bool promiscuous = true;

  // Live vs Forensic operating mode (see AnalysisMode above). Resolved through
  // is_forensic(), which honors Auto by inspecting the capture source.
  AnalysisMode analysis_mode = AnalysisMode::Auto;

  // Inline mode (WinDivert) — intercept packets in the Windows TCP/IP stack
  // instead of passively tapping via pcap. Enables IPS-style blocking.
  bool use_windivert = false;          // true = WinDivert inline, false = pcap tap
  bool inline_block = false;           // IPS: drop traffic from flagged sources
  std::string windivert_filter = "tcp"; // WinDivert packet filter expression
  // IPS safety: comma-separated source IPs that must NEVER be blocked
  // (gateways, DNS, domain controllers). Prevents a spoofed-source attack
  // from tricking the IPS into DoSing critical infrastructure.
  std::string block_allowlist;

  // Threat-intelligence feed: directory containing updatable rule files
  // (bad_ja3.txt, bad_domains.txt, bad_ips.txt, signatures.txt). Empty =
  // built-in detection only.
  std::string rules_dir;

  // Behavioral C2 detection (clean-room Markov models trained on CTU-13).
  // Directory containing behavioral.botnet.model + behavioral.normal.model.
  // Empty = disabled (live C2 detection falls back to the beaconing detector).
  std::string behavioral_models_dir;
  // Log-likelihood-ratio threshold (score_botnet - score_normal) above which a
  // connection is flagged. See tools/train_behavioral eval sweep for tuning.
  double behavioral_threshold = 0.0;

  // Logging
  int log_level = 1; // 0=DEBUG, 1=INFO, 2=WARN, 3=ERROR

  // Inputs (populated from CLI)
  std::string interface;
  std::string openvino_model_path;
  std::string llama_model_path;

  std::string parse_error;

  static WirewolfConfig parse(int argc, char *argv[]) {
    WirewolfConfig cfg;

    if (argc < 4) {
      return cfg; // Caller checks validity
    }

    cfg.interface = argv[1];
    cfg.openvino_model_path = argv[2];
    cfg.llama_model_path = argv[3];

    try {
      for (int i = 4; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--log-level" && i + 1 < argc) {
          cfg.log_level = std::stoi(argv[++i]);
          if (cfg.log_level < 0 || cfg.log_level > 3) {
            cfg.parse_error = "log-level must be 0-3";
            return cfg;
          }
        } else if (arg == "--queue-capacity" && i + 1 < argc) {
          cfg.queue_capacity = std::stoull(argv[++i]);
          if (cfg.queue_capacity == 0) {
            cfg.parse_error = "queue-capacity must be > 0";
            return cfg;
          }
        } else if (arg == "--payload-limit" && i + 1 < argc) {
          cfg.payload_char_limit = std::stoull(argv[++i]);
          if (cfg.payload_char_limit == 0) {
            cfg.parse_error = "payload-limit must be > 0";
            return cfg;
          }
        } else if (arg == "--max-tokens" && i + 1 < argc) {
          cfg.max_tokens = std::stoi(argv[++i]);
          if (cfg.max_tokens <= 0) {
            cfg.parse_error = "max-tokens must be > 0";
            return cfg;
          }
        } else if (arg == "--max-llm-flows" && i + 1 < argc) {
          cfg.max_llm_flows = std::stoull(argv[++i]);
        } else if (arg == "--max-flow-size" && i + 1 < argc) {
          cfg.max_flow_payload_bytes = std::stoull(argv[++i]);
          if (cfg.max_flow_payload_bytes == 0) {
            cfg.parse_error = "max-flow-size must be > 0";
            return cfg;
          }
        } else if (arg == "--openvino") {
          cfg.openvino_enabled = true;
        } else if (arg == "--entropy-high" && i + 1 < argc) {
          cfg.entropy_high_threshold = std::stof(argv[++i]);
        } else if (arg == "--entropy-low" && i + 1 < argc) {
          cfg.entropy_low_threshold = std::stof(argv[++i]);
        } else if (arg == "--no-promisc") {
          cfg.promiscuous = false;
        } else if (arg == "--behavioral-models" && i + 1 < argc) {
          cfg.behavioral_models_dir = argv[++i];
        } else if (arg == "--behavioral-threshold" && i + 1 < argc) {
          cfg.behavioral_threshold = std::stod(argv[++i]);
        } else if (arg == "--mode" && i + 1 < argc) {
          std::string m = argv[++i];
          if (m == "live")
            cfg.analysis_mode = AnalysisMode::Live;
          else if (m == "forensic")
            cfg.analysis_mode = AnalysisMode::Forensic;
          else if (m == "auto")
            cfg.analysis_mode = AnalysisMode::Auto;
          else {
            cfg.parse_error = "mode must be live|forensic|auto";
            return cfg;
          }
        }
      }
    } catch (const std::exception &e) {
      cfg.parse_error = std::string("Invalid argument: ") + e.what();
    }

    return cfg;
  }

  bool valid() const {
    if (!parse_error.empty() || llama_model_path.empty())
      return false;
    // WinDivert inline mode uses a filter expression, not an interface name.
    // Tap (pcap) mode requires an interface or PCAP file.
    if (!use_windivert && interface.empty())
      return false;
    // OpenVINO model is only required when OpenVINO is actually enabled.
    if (openvino_enabled && openvino_model_path.empty())
      return false;
    return true;
  }

  bool is_offline_capture() const {
    auto ends_with = [](const std::string &s, const std::string &suffix) {
      return s.size() >= suffix.size() &&
             s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
    };
    return ends_with(interface, ".pcap") || ends_with(interface, ".pcapng");
  }

  // Resolve the operating mode, honoring Auto. Forensic = deep LLM analysis;
  // Live = fast detectors decide and signature hits skip the LLM.
  bool is_forensic() const {
    if (analysis_mode == AnalysisMode::Forensic)
      return true;
    if (analysis_mode == AnalysisMode::Live)
      return false;
    return is_offline_capture(); // Auto
  }

  static constexpr bool openvino_compiled() {
#ifdef WIREWOLF_USE_OPENVINO
    return true;
#else
    return false;
#endif
  }
};
