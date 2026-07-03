#pragma once
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

struct ConnectionId {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;

  bool operator==(const ConnectionId &o) const {
    return src_ip == o.src_ip && dst_ip == o.dst_ip && src_port == o.src_port &&
           dst_port == o.dst_port;
  }
};

template <class T> inline void hash_combine(std::size_t &seed, const T &v) {
  std::hash<T> hasher;
  seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

namespace std {
template <> struct hash<ConnectionId> {
  std::size_t operator()(const ConnectionId &k) const {
    std::size_t res = 0;
    hash_combine(res, k.src_ip);
    hash_combine(res, k.dst_ip);
    hash_combine(res, k.src_port);
    hash_combine(res, k.dst_port);
    return res;
  }
};
} // namespace std

struct FlowData {
  ConnectionId id{};
  std::vector<uint8_t> reassembled_payload;
  // Canonicalized payload for evasion-resistant detection (URL/unicode
  // decoded, comments stripped, case/whitespace folded). Raw bytes above
  // are kept for verbatim snippet reporting.
  std::string normalized_payload;
  std::string protocol_tag;
  // TLS handshake metadata (extracted without decryption). Populated for
  // HTTPS/TLS flows so alerts can report the destination and client fingerprint.
  std::string tls_sni;  // Server Name Indication (destination hostname)
  std::string tls_ja3;  // JA3 fingerprint hash (client TLS fingerprint)
  double timestamp = 0.0;
  double inter_arrival_time = 0.0;
  double length_variance = 0.0;
  size_t packet_count = 0;
  // Behavioral C2 signal (Markov LLR over the flow's 4-tuple): NOT a standalone
  // verdict. F3 showed standalone behavioral precision ~0.02 on real pcaps, so
  // it only escalates this flow to the LLM with elevated priority — the LLM (or
  // analyst) adjudicates. Never raises an alert on its own.
  bool behavioral_suspect = false;

  FlowData() = default;
  FlowData(const FlowData &) = delete;
  FlowData &operator=(const FlowData &) = delete;
  FlowData(FlowData &&) = default;
  FlowData &operator=(FlowData &&) = default;
};

using FlowPtr = std::unique_ptr<FlowData>;
