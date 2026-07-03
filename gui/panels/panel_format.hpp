#pragma once
// Shared formatting helpers for the ImGui panels: IP / endpoint / timestamp
// rendering into a caller-provided buffer. Header-only so each panel keeps its
// own translation unit but there's a single copy of the logic.

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <ctime>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

namespace gui {

// Format an IPv4 address stored in network byte order. Reads bytes directly to
// avoid endianness issues with bit-shifting.
inline void format_ip(uint32_t ip_net_order, char *buf, size_t buf_size) {
  auto *b = reinterpret_cast<const uint8_t *>(&ip_net_order);
  std::snprintf(buf, buf_size, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

// Format an endpoint (IP:port), converting the port from network order.
inline void format_endpoint(uint32_t ip, uint16_t port_net_order, char *buf,
                            size_t buf_size) {
  char ip_buf[32];
  format_ip(ip, ip_buf, sizeof(ip_buf));
  std::snprintf(buf, buf_size, "%s:%u", ip_buf, ntohs(port_net_order));
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
  std::snprintf(buf, buf_size, "%02d:%02d:%02d.%03d", tm_buf.tm_hour,
                tm_buf.tm_min, tm_buf.tm_sec, static_cast<int>(ms.count()));
}

} // namespace gui
