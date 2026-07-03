#include "alert_json.hpp"
#include <cstdio>

std::string json_escape(std::string_view s) {
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
        std::snprintf(buf, sizeof(buf), "\\u%04x",
                      static_cast<unsigned char>(c));
        out += buf;
      } else {
        out += c;
      }
    }
  }
  return out;
}

std::string build_alert_json(std::string_view threat_type,
                             const SeverityInfo &sev, std::string_view snippet) {
  return "{\"threat_type\": \"" + json_escape(threat_type) +
         "\", \"severity\": \"" + json_escape(sev.format()) +
         "\", \"cvss\": " + std::to_string(sev.cvss) +
         ", \"snippet\": \"" + json_escape(snippet) + "\"}";
}
