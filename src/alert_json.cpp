#include "alert_json.hpp"
#include <format>

std::string json_escape(std::string_view s) {
  std::string out;
  out.reserve(s.size() + 16);
  for (char c : s) {
    switch (c) {
    case '"':  out += R"(\")";  break;
    case '\\': out += R"(\\)";  break;
    case '\n': out += "\\n";  break;
    case '\r': out += "\\r";  break;
    case '\t': out += "\\t";  break;
    default:
      if (static_cast<unsigned char>(c) < 0x20)
        out += std::format("\\u{:04x}", static_cast<unsigned char>(c));
      else
        out += c;
    }
  }
  return out;
}

std::string build_alert_json(std::string_view threat_type,
                             const SeverityInfo &sev, std::string_view snippet) {
  // {:.6f} matches the historical std::to_string(float) formatting so the
  // emitted JSON is byte-identical to the pre-refactor producers.
  return std::format(
      R"({{"threat_type": "{}", "severity": "{}", "cvss": {:.6f}, "snippet": "{}"}})",
      json_escape(threat_type), json_escape(sev.format()), sev.cvss,
      json_escape(snippet));
}
