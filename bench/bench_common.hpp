#pragma once
// Shared helpers for the bench tools (benchmark.cpp, probe.cpp): an
// order-independent IP-pair key, a dotted-quad parser, and a whitespace trim.
// Kept header-only so both standalone tools link the exact same code.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>

namespace bench {

// Unordered IP pair key, so direction doesn't matter for scoring.
using PairKey = uint64_t;

inline PairKey make_pair_key(uint32_t a, uint32_t b) {
  uint32_t lo = std::min(a, b);
  uint32_t hi = std::max(a, b);
  return (static_cast<uint64_t>(lo) << 32) | hi;
}

// Dotted-quad -> network byte order (matches the IP-header layout the engine
// uses internally).
inline uint32_t parse_ip(const std::string &s) {
  uint32_t ip = 0;
  unsigned o0;
  unsigned o1;
  unsigned o2;
  unsigned o3;
#ifdef _WIN32
  if (sscanf_s(s.c_str(), "%u.%u.%u.%u", &o0, &o1, &o2, &o3) == 4)
#else
  if (sscanf(s.c_str(), "%u.%u.%u.%u", &o0, &o1, &o2, &o3) == 4)
#endif
    ip = static_cast<uint32_t>(o0) | (o1 << 8) | (o2 << 16) | (o3 << 24);
  return ip;
}

inline std::string trim(const std::string &s) {
  size_t a = s.find_first_not_of(" \t\r\n");
  if (a == std::string::npos) return "";
  size_t b = s.find_last_not_of(" \t\r\n");
  return s.substr(a, b - a + 1);
}

} // namespace bench
