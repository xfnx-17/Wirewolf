#pragma once
#include "behavioral_model.hpp"
#include "config.hpp"
#include "packet_types.hpp"
#include "proxy_db.hpp"
#include "wirewolf_types.hpp"
#include "thread_safe_queue.hpp"
#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>

#ifndef WPCAP
#define WPCAP
#endif
#ifndef HAVE_REMOTE
#define HAVE_REMOTE
#endif
#include <pcap.h>
#else
#include <pcap.h>
#endif

struct ConnectionState {
  uint32_t expected_seq = 0;
  std::map<uint32_t, std::vector<uint8_t>> out_of_order_segments;
  std::vector<uint8_t> payload;
  bool syn_received = false;
  bool fin_received = false;
  double last_packet_time = 0.0;
  double inter_arrival_sum = 0.0;
  size_t packet_count = 0;
  size_t length_sum = 0;
  size_t length_sq_sum = 0;

  ConnectionState() = default;
};

// Tracks per-source-IP connection patterns to detect volumetric attacks
// (port scans, SYN floods, brute force, worm propagation).
struct SourceTracker {
  std::unordered_set<uint16_t> dst_ports; // unique dst ports (port scan)
  std::unordered_map<uint16_t, size_t> port_syn_counts; // SYN per dst port
  size_t total_syns = 0;
  double first_syn_time = 0.0; // timestamp of first SYN (for rate calc)

  // Worm scan: unique dst IPs targeted on a single port
  // Key = dst_port (network order), Value = set of unique dst IPs
  std::unordered_map<uint16_t, std::unordered_set<uint32_t>> port_dst_ips;

  // All distinct external (public) destination IPs this source contacted,
  // across every port. Used to credit the whole footprint of a host once it
  // is confirmed compromised (e.g. a spam bot) — operationally you quarantine
  // the host, so all of its connections become in-scope.
  std::unordered_set<uint32_t> ext_dsts;

  // TTL baseline for spoofing detection. A real source presents a stable
  // initial-TTL (OS-dependent: 64 Linux/Mac, 128 Windows, 255 net gear).
  // A change in the estimated initial-TTL for the same source IP means two
  // different stacks are presenting that address — a spoofing indicator.
  uint8_t initial_ttl = 0; // 0 = unset; otherwise 64/128/255
};

// Tracks per-destination connection timing for C2 beaconing detection.
// Key in the map is a composite of (src_ip, dst_ip, dst_port).
struct BeaconTracker {
  std::vector<double> syn_timestamps; // timestamps of SYN packets
  uint32_t src_ip = 0;
  uint32_t dst_ip = 0;
  uint16_t dst_port = 0; // network byte order
};

class TcpReassembler {
public:
  TcpReassembler(const WirewolfConfig &config,
                 ThreadSafeQueue<FlowPtr> &out_queue);
  ~TcpReassembler();
  void start();
  void stop();
  void set_on_threat_detected(OnThreatDetected cb) { threat_callback_ = cb; }

  // Training export: accumulate per-4-tuple behavioral flows WITHOUT scoring
  // (no models needed), then dump the encoded state strings after a capture.
  // Used by the offline export tool so models are trained on the SAME encoder
  // output the live engine produces (no train/runtime drift).
  void set_behavioral_export(bool enable) { beh_export_ = enable; }
  void dump_behavioral_states(const std::string &path);

  // IPS: block all future traffic from this source IP (network byte order).
  // Thread-safe; called by the pipeline when a threat is confirmed.
  // No-op if the IP is on the never-block allowlist (critical assets).
  void block_source(uint32_t src_ip_net_order);
  void unblock_source(uint32_t src_ip_net_order); // reversible
  bool is_blocked(uint32_t src_ip_net_order) const;
  // Parse a comma-separated allowlist of IPs that must never be blocked.
  void set_block_allowlist(const std::string &csv);

  // IPS stats (for the dashboard).
  size_t blocked_packet_count() const {
    return blocked_packet_count_.load(std::memory_order_relaxed);
  }
  size_t blocked_source_count() const {
    std::lock_guard<std::mutex> lock(blocklist_mutex_);
    return blocked_ips_.size();
  }

private:
  static void packet_handler(u_char *user_data,
                             const struct pcap_pkthdr *pkthdr,
                             const u_char *packet);
  void process_packet(const struct pcap_pkthdr *pkthdr, const u_char *packet);
  // Shared core: process a raw IP packet (no link-layer header).
  // Returns the source IP (network order) so the caller can decide to
  // re-inject or drop in inline mode. Sets *is_threat if a synchronous
  // connection-level anomaly fired for this packet's source.
  uint32_t process_ip_packet(const uint8_t *ip_packet, uint32_t len,
                             double timestamp);
  void run_pcap();
#ifdef WIREWOLF_USE_WINDIVERT
  void run_windivert();
#endif
  void check_complete_flows();
  void flush_all_flows();
  void check_connection_anomalies(uint32_t src_ip, uint32_t dst_ip,
                                  uint16_t dst_port, bool is_syn,
                                  double timestamp, uint8_t ttl);
  void check_beaconing_at_flush();
  void check_mass_mailing_at_flush();
  FlowPtr make_flow_data();

  // Behavioral C2 scoring: record one completed connection as a flow under its
  // 4-tuple (src,dst,dport — src-port collapsed, like the binetflow grouping),
  // then score the accumulated state string against the trained Markov models.
  void record_and_score_behavioral(const ConnectionId &id, uint64_t tot_bytes,
                                   double start_time, double duration);
  // Stable hash of a connection's behavioral 4-tuple (src,dst,dport) — used to
  // both flag a suspect connection and, at flow-emit time, tag its FlowData.
  size_t beh_key(const ConnectionId &id) const;

  pcap_t *handle = nullptr;
#ifdef WIREWOLF_USE_WINDIVERT
  void *divert_handle_ = nullptr; // HANDLE from WinDivertOpen
#endif
  ThreadSafeQueue<FlowPtr> &output_queue;
  std::atomic<bool> running{false};
  const WirewolfConfig &cfg;

  // IPS blocklist of source IPs (network byte order). Packets from these
  // sources are dropped (not re-injected) in WinDivert inline mode.
  mutable std::mutex blocklist_mutex_;
  std::unordered_set<uint32_t> blocked_ips_;
  std::unordered_set<uint32_t> allowlist_ips_; // never blocked (critical assets)
  std::atomic<size_t> blocked_packet_count_{0};

  std::unordered_map<ConnectionId, ConnectionState> connections;

  // Connection-level anomaly tracking
  ProxyDb proxy_db_; // optional threat-intel (IP2Location PX12) lookup
  std::unordered_map<uint32_t, SourceTracker> source_trackers_;
  std::unordered_set<size_t> alerted_anomalies_; // dedup by hash
  OnThreatDetected threat_callback_;

  // C2 beaconing tracking: key = hash(src_ip, dst_ip, dst_port)
  std::unordered_map<size_t, BeaconTracker> beacon_trackers_;

  // Behavioral C2 detection (clean-room Markov). Loaded from
  // cfg.behavioral_models_dir; disabled if not present.
  bool behavioral_ready_ = false;
  bool beh_export_ = false; // accumulate-only mode for offline training export
  behavioral::BehavioralConfig beh_cfg_;
  behavioral::MarkovModel beh_botnet_;
  behavioral::MarkovModel beh_normal_;
  struct BehConn {
    uint32_t src = 0, dst = 0;
    uint16_t dport = 0;
    std::vector<behavioral::Flow> flows;
  };
  std::unordered_map<size_t, BehConn> beh_conns_; // key = hash(src,dst,dport)
  std::unordered_set<size_t> beh_alerted_;        // dedup by 4-tuple
  // 4-tuples whose Markov LLR cleared the threshold. NOT alerted directly: a
  // flagged connection's flows are tagged behavioral_suspect at emit time so
  // the NPU filter escalates them to the LLM for adjudication (LLM-gated).
  std::unordered_set<size_t> beh_suspicious_;
  // Endpoints seen speaking BitTorrent — P2P fan-out mimics botnet C2, so these
  // peers are excluded from behavioral scoring (unencrypted BT detection).
  std::unordered_set<uint32_t> p2p_peers_;
  static constexpr size_t MAX_BEH_CONNS = 100000;

  // Eviction: periodic cleanup of stale tracking state
  double last_eviction_time_ = 0.0;
  static constexpr double EVICTION_INTERVAL_SEC = 60.0;
  static constexpr double CONNECTION_TIMEOUT_SEC = 120.0;
  static constexpr size_t MAX_SOURCE_TRACKERS = 100000;
  static constexpr size_t MAX_BEACON_TRACKERS = 50000;
  static constexpr size_t MAX_DEDUP_HASHES = 100000;
  // Hard cap on the reassembly connection table. Without this a SYN flood
  // (each spoofed source port = a new flow) grows the table without bound and
  // the periodic full-map eviction degrades toward O(n^2) — a self-inflicted
  // DoS on the sensor. When full we shed new flows' reassembly; connection-
  // level anomaly detection still fires, so the flood is still detected.
  static constexpr size_t MAX_CONNECTIONS = 50000;
  std::atomic<size_t> shed_count_{0}; // flows whose reassembly was shed
  double last_force_evict_time_ = 0.0;
  void evict_stale_state(double current_time);
  void force_evict_oldest(double current_time);

};
