#pragma once
#include "config.hpp"
#include "packet_types.hpp"
#include "wirewolf_types.hpp"
#include "thread_safe_queue.hpp"
#include "threat_feed.hpp"
#include <atomic>
#include <memory>
#include <thread>
#include <unordered_set>
#include <vector>

#ifdef WIREWOLF_USE_OPENVINO
#include <openvino/openvino.hpp>
#endif

class NpuFilter {
public:
  // CNN model constants
  static constexpr size_t CNN_INPUT_SEQ_LEN = 512;
  static constexpr int32_t CNN_PAD_TOKEN = 256;

  NpuFilter(const WirewolfConfig &config, ThreadSafeQueue<FlowPtr> &in_queue,
            ThreadSafeQueue<FlowPtr> &out_queue);
  void start();
  void stop();
  void set_flow_event_callback(OnFlowEvent cb);

  size_t get_passed_count() const {
    return passed_count.load(std::memory_order::relaxed);
  }
  size_t get_filtered_count() const {
    return filtered_count.load(std::memory_order::relaxed);
  }
  size_t get_dedup_count() const {
    return dedup_count.load(std::memory_order::relaxed);
  }
  std::string get_device() const {
#ifdef WIREWOLF_USE_OPENVINO
    if (openvino_available)
      return openvino_device;
#endif
    return "Statistical";
  }

private:
  void worker_loop();
  void extract_features(FlowData *flow, std::vector<float> &features);
  bool statistical_filter(const std::vector<float> &features,
                          const FlowData *flow);
#ifdef WIREWOLF_USE_OPENVINO
  void prepare_byte_tensor(const FlowData *flow, ov::Tensor &tensor);
#endif
  bool detect_heartbleed(const FlowData *flow) const;
  bool detect_spnego(const FlowData *flow) const;
  bool detect_benign_http(const FlowData *flow) const;
  bool detect_ftp_activity(const FlowData *flow) const;
  bool detect_credential_content(const FlowData *flow) const;
  bool detect_http_bruteforce(const FlowData *flow) const;
  bool detect_smb_exploit(const FlowData *flow) const;
  bool detect_rat_protocol(const FlowData *flow) const;
  // Anti-evasion: scan the canonicalized payload for injection signatures
  // that obfuscation (URL/unicode encoding, comments) hid from raw matching.
  bool detect_obfuscated_injection(const FlowData *flow) const;

  // Encrypted-traffic analysis: parse a TLS ClientHello (no decryption),
  // extract SNI + JA3, and decide if the flow is suspicious. Returns:
  //   0 = not TLS (fall through to normal handling)
  //   1 = TLS, suspicious  (flow->protocol_tag set, escalate)
  //   2 = TLS, benign      (filter out; encrypted payload is useless to LLM)
  int inspect_tls(FlowData *flow) const;

  ThreadSafeQueue<FlowPtr> &input_queue;
  ThreadSafeQueue<FlowPtr> &output_queue;
  std::atomic<bool> running{false};
  std::thread worker;
  const WirewolfConfig &cfg;

  std::atomic<size_t> passed_count{0};
  std::atomic<size_t> filtered_count{0};
  std::atomic<size_t> dedup_count{0};
  OnFlowEvent flow_event_callback_;

  // Payload dedup: hash(dst_ip, dst_port, first 256 bytes of payload)
  static constexpr size_t MAX_DEDUP_HASHES = 100000;
  std::unordered_set<size_t> seen_payload_hashes_;

  // Updatable threat-intelligence feed (JA3, domains, IPs, content sigs).
  ThreatFeed threat_feed_;

#ifdef WIREWOLF_USE_OPENVINO
  ov::Core core;
  ov::CompiledModel compiled_model;
  ov::InferRequest infer_request;
  bool openvino_available = false;
  std::string openvino_device; // "NPU", "CPU", etc.
#endif
};
