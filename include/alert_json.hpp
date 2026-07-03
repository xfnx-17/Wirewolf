#pragma once
// alert_json.hpp — one place that builds the canonical threat-alert JSON.
//
// The same {"threat_type","severity","cvss","snippet"} object is emitted from
// the LLM worker and from every connection-level anomaly in the reassembler,
// and parsed back by PipelineController. Keeping the shape in a single helper
// means the producers and the parser can never drift.

#include "wirewolf_types.hpp" // SeverityInfo
#include <string>
#include <string_view>

// JSON-escape a string value: quotes, backslashes, and control characters
// (payloads are attacker-controlled, so this must be robust).
std::string json_escape(std::string_view s);

// Canonical alert object:
//   {"threat_type": "<t>", "severity": "<sev.format()>",
//    "cvss": <sev.cvss>, "snippet": "<snip>"}
// threat_type and snippet are escaped; caller passes raw values.
std::string build_alert_json(std::string_view threat_type,
                             const SeverityInfo &sev, std::string_view snippet);
