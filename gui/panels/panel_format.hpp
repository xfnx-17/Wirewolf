#pragma once
// Shared formatting helpers for the ImGui panels: IP / endpoint / timestamp
// rendering into a caller-provided buffer. Header-only so each panel keeps its
// own translation unit but there's a single copy of the logic.

#include <chrono>
#include <cstdint>
#include <ctime>
#include <format>

namespace gui {

// Host-order 16-bit byte swap (avoids pulling in <winsock2.h> just for ntohs).
inline uint16_t bswap16(uint16_t v) {
  return static_cast<uint16_t>((v << 8) | (v >> 8));
}

// Format an IPv4 address stored in network byte order. Reads bytes directly to
// avoid endianness issues with bit-shifting.
inline void format_ip(uint32_t ip_net_order, char *buf, size_t buf_size) {
  const auto *b = reinterpret_cast<const uint8_t *>(&ip_net_order);
  auto res = std::format_to_n(buf, buf_size - 1, "{}.{}.{}.{}", b[0], b[1],
                              b[2], b[3]);
  *res.out = '\0';
}

// Format an endpoint (IP:port), converting the port from network order.
inline void format_endpoint(uint32_t ip, uint16_t port_net_order, char *buf,
                            size_t buf_size) {
  const auto *b = reinterpret_cast<const uint8_t *>(&ip);
  auto res = std::format_to_n(buf, buf_size - 1, "{}.{}.{}.{}:{}", b[0], b[1],
                              b[2], b[3], bswap16(port_net_order));
  *res.out = '\0';
}

// Format a timestamp as HH:MM:SS.mmm in local time.
inline void format_time(std::chrono::system_clock::time_point tp, char *buf,
                        size_t buf_size) {
  auto t = std::chrono::system_clock::to_time_t(tp);
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                tp.time_since_epoch()) %
            1000;
  std::tm tm_buf{};
#ifdef _WIN32
  localtime_s(&tm_buf, &t);
#else
  localtime_r(&t, &tm_buf);
#endif
  auto res = std::format_to_n(buf, buf_size - 1, "{:02}:{:02}:{:02}.{:03}",
                              tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
                              static_cast<int>(ms.count()));
  *res.out = '\0';
}

} // namespace gui
