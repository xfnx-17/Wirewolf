#pragma once
#include "packet_types.hpp"
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <functional>
#include <string>

// CVSS v4.0 severity classification (CVSS-B base score)
// https://www.first.org/cvss/v4.0/specification-document
//
// CVSS 4.0 key changes from 3.1:
//   - Removed Scope (S), replaced by split impact: Vulnerable System
//     (VC/VI/VA) vs Subsequent System (SC/SI/SA)
//   - Added Attack Requirements (AT): None or Present
//   - User Interaction: None / Passive / Active (was None / Required)
//   - New Supplemental metrics group (not scored here)
//   - Qualitative ratings unchanged: Critical 9.0-10.0, High 7.0-8.9,
//     Medium 4.0-6.9, Low 0.1-3.9, None 0.0

enum class Severity { Info, Low, Medium, High, Critical };

struct SeverityInfo {
  Severity level;
  float cvss;

  const char *label() const {
    switch (level) {
    case Severity::Critical: return "Critical";
    case Severity::High:     return "High";
    case Severity::Medium:   return "Medium";
    case Severity::Low:      return "Low";
    case Severity::Info:     return "Info";
    }
    return "Unknown";
  }

  static const char *cvss_rating(float score) {
    if (score >= 9.0f) return "Critical";
    if (score >= 7.0f) return "High";
    if (score >= 4.0f) return "Medium";
    if (score >= 0.1f) return "Low";
    return "None";
  }

  std::string format() const {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%s (CVSS 4.0: %.1f/%s)",
                  label(), cvss, cvss_rating(cvss));
    return buf;
  }
};

// Detection confidence (0..1) for a fired alert. There is no calibrated
// probability model here, so this is a transparent heuristic over signals the
// backend actually has:
//   - CVSS base score (higher-impact threats score higher), and
//   - whether the detection was deterministic (a signature/rule/connection
//     anomaly that matched exactly) vs. LLM-classified (which already passed
//     verbatim-snippet validation + false-positive suppression upstream).
// Deterministic hits get a higher floor because they don't depend on model
// judgement. This is intentionally explainable, not a black-box score.
inline float confidence_for(const SeverityInfo &sev, bool deterministic) {
  float base = deterministic ? 0.78f : 0.55f;
  float c = base + (sev.cvss / 10.0f) * (deterministic ? 0.20f : 0.40f);
  if (c > 0.99f) c = 0.99f;
  if (c < 0.05f) c = 0.05f;
  return c;
}

// Per-threat-type CVSS v4.0 base scores (CVSS-B).
// Reference: https://www.first.org/cvss/calculator/4.0
//
// CVSS 4.0 base vector format:
//   AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
//
// Key differences from v3.1:
//   - Scope (S) removed; replaced by Subsequent System impact (SC/SI/SA)
//   - Attack Requirements (AT): None = no special conditions, Present = needs
//     specific config, race condition, or deployment-dependent prerequisite
//   - User Interaction: None / Passive (viewing) / Active (clicking, installing)
//   - Scores shift: XSS drops (UI:P, subsequent-only impact); RCE attacks
//     without subsequent impact cap at 9.3; subsequent-system impact needed
//     for 9.4+; 10.0 requires max impact on both systems
//
// ═══════════════════════════════════════════════════════════════════
// WEB APPLICATION ATTACKS
// ═══════════════════════════════════════════════════════════════════
//   SQLi                    — 9.3: AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
//   Command Injection       — 9.3: AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
//   SSTI                    — 9.3: AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
//   Deserialization Attack  — 9.3: AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
//   File Inclusion          — 9.3: AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
//   LDAP Injection          — 9.3: AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
//   XPath Injection         — 9.3: AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
//   NoSQL Injection         — 9.3: AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
//   Malicious File Upload   — 9.3: AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
//   SSRF                    — 8.7: AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:N/SA:N
//   XXE                     — 8.7: AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:H/SI:N/SA:N
//   HTTP Request Smuggling  — 8.3: AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
//   Path Traversal          — 8.7: AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
//   Prototype Pollution     — 8.3: AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N
//   CSRF                    — 6.3: AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N
//   XSS                     — 5.3: AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N
//   HTTP Response Splitting — 5.3: AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N
//   CRLF Injection          — 5.3: AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N
//   Open Redirect           — 4.0: AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N
//
// ═══════════════════════════════════════════════════════════════════
// KNOWN CVE EXPLOITS (protocol-level)
// ═══════════════════════════════════════════════════════════════════
//   Log4Shell (CVE-2021-44228)    — 10.0: AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
//   Shellshock (CVE-2014-6271)    — 9.3:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
//   Spring4Shell (CVE-2022-22965) — 9.3:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
//   Apache Struts RCE             — 9.3:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
//   SMB Exploit (MS17-010)        — 9.4:  AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
//   Heartbleed (CVE-2014-0160)    — 8.7:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
//
// ═══════════════════════════════════════════════════════════════════
// MALWARE / C2 / BACKDOOR
// ═══════════════════════════════════════════════════════════════════
//   Worm Propagation Scan   — 10.0: AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
//   Ransomware C2           — 10.0: AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
//   Reverse Shell           — 9.3:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
//   Webshell                — 9.3:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
//   Malware Payload         — 9.3:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
//   RAT C2                  — 9.3:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L
//   C2 Beaconing            — 9.3:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L
//   Botnet Communication    — 9.3:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L
//   Dropper Download        — 8.6:  AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
//   Cryptominer Traffic     — 8.7:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H
//
// ═══════════════════════════════════════════════════════════════════
// DATA EXFILTRATION / CREDENTIAL THEFT
// ═══════════════════════════════════════════════════════════════════
//   Data Exfiltration       — 9.3:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:N
//   Credential Theft        — 9.3:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:N
//   DNS Exfiltration        — 8.7:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
//   Session Hijacking       — 8.3:  AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
//
// ═══════════════════════════════════════════════════════════════════
// AUTHENTICATION ATTACKS
// ═══════════════════════════════════════════════════════════════════
//   Brute Force             — 7.7:  AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
//   SSH Brute Force         — 7.7:  AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
//   Credential Stuffing     — 7.7:  AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
//   Password Spraying       — 7.7:  AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
//   Kerberoasting           — 7.1:  AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
//
// ═══════════════════════════════════════════════════════════════════
// DENIAL OF SERVICE
// ═══════════════════════════════════════════════════════════════════
//   DNS Amplification       — 9.2:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H
//   DDoS                    — 8.7:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N
//   Slowloris               — 8.7:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N
//   HTTP Flood              — 8.7:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N
//   ReDoS                   — 8.7:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N
//
// ═══════════════════════════════════════════════════════════════════
// RECONNAISSANCE / ENUMERATION
// ═══════════════════════════════════════════════════════════════════
//   Port Scan               — 6.9:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N
//   Directory Enumeration   — 6.9:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N
//   Version Fingerprinting  — 6.9:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N
//   Vulnerability Scanning  — 6.9:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N
//   User Enumeration        — 6.9:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N
//
// ═══════════════════════════════════════════════════════════════════
// NETWORK / PROTOCOL ATTACKS
// ═══════════════════════════════════════════════════════════════════
//   DNS Tunneling           — 8.7:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
//   DNS Poisoning           — 8.3:  AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:H/SA:N
//   DNS Rebinding           — 6.0:  AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
//   TLS Downgrade           — 7.7:  AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
//   SMTP Relay Abuse        — 6.9:  AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N

inline SeverityInfo severity_for_threat(const std::string &threat_type) {
  // --- Web Application Attacks ---
  if (threat_type == "SQLi")
    return {Severity::Critical, 9.3f};
  if (threat_type == "Command Injection")
    return {Severity::Critical, 9.3f};
  if (threat_type == "SSTI")
    return {Severity::Critical, 9.3f};
  if (threat_type == "Deserialization Attack")
    return {Severity::Critical, 9.3f};
  if (threat_type == "File Inclusion")
    return {Severity::Critical, 9.3f};
  if (threat_type == "LDAP Injection")
    return {Severity::Critical, 9.3f};
  if (threat_type == "XPath Injection")
    return {Severity::Critical, 9.3f};
  if (threat_type == "NoSQL Injection")
    return {Severity::Critical, 9.3f};
  if (threat_type == "Malicious File Upload")
    return {Severity::Critical, 9.3f};
  if (threat_type == "SSRF")
    return {Severity::High, 8.7f};
  if (threat_type == "XXE")
    return {Severity::High, 8.7f};
  if (threat_type == "Path Traversal")
    return {Severity::High, 8.7f};
  if (threat_type == "HTTP Request Smuggling")
    return {Severity::High, 8.3f};
  if (threat_type == "Prototype Pollution")
    return {Severity::High, 8.3f};
  if (threat_type == "CSRF")
    return {Severity::Medium, 6.3f};
  if (threat_type == "XSS")
    return {Severity::Medium, 5.3f};
  if (threat_type == "HTTP Response Splitting")
    return {Severity::Medium, 5.3f};
  if (threat_type == "CRLF Injection")
    return {Severity::Medium, 5.3f};
  if (threat_type == "Open Redirect")
    return {Severity::Medium, 4.0f};

  // --- Known CVE Exploits ---
  if (threat_type == "Log4Shell")
    return {Severity::Critical, 10.0f};
  if (threat_type == "SMB Exploit")
    return {Severity::Critical, 9.4f};
  if (threat_type == "Shellshock")
    return {Severity::Critical, 9.3f};
  if (threat_type == "Spring4Shell")
    return {Severity::Critical, 9.3f};
  if (threat_type == "Apache Struts RCE")
    return {Severity::Critical, 9.3f};
  if (threat_type == "Heartbleed")
    return {Severity::High, 8.7f};

  // --- Malware / C2 / Backdoor ---
  if (threat_type == "Worm Propagation Scan")
    return {Severity::Critical, 10.0f};
  if (threat_type == "Ransomware C2")
    return {Severity::Critical, 10.0f};
  if (threat_type == "Reverse Shell")
    return {Severity::Critical, 9.3f};
  if (threat_type == "Webshell")
    return {Severity::Critical, 9.3f};
  if (threat_type == "Malware Payload")
    return {Severity::Critical, 9.3f};
  if (threat_type == "RAT C2")
    return {Severity::Critical, 9.3f};
  if (threat_type == "C2 Beaconing")
    return {Severity::Critical, 9.3f};
  if (threat_type == "Botnet Communication")
    return {Severity::Critical, 9.3f};
  if (threat_type == "Spam Bot")
    return {Severity::High, 8.1f};
  if (threat_type == "Suspicious Transfer")
    return {Severity::Medium, 5.3f};
  if (threat_type == "Botnet Host")
    return {Severity::Critical, 9.3f};
  if (threat_type == "Dropper Download")
    return {Severity::High, 8.6f};
  if (threat_type == "Cryptominer Traffic")
    return {Severity::High, 8.7f};

  // --- Data Exfiltration / Credential Theft ---
  if (threat_type == "Data Exfiltration")
    return {Severity::Critical, 9.3f};
  if (threat_type == "Credential Theft")
    return {Severity::Critical, 9.3f};
  if (threat_type == "DNS Exfiltration")
    return {Severity::High, 8.7f};
  if (threat_type == "Session Hijacking")
    return {Severity::High, 8.3f};

  // --- Authentication Attacks ---
  if (threat_type == "Brute Force")
    return {Severity::High, 7.7f};
  if (threat_type == "SSH Brute Force")
    return {Severity::High, 7.7f};
  if (threat_type == "Credential Stuffing")
    return {Severity::High, 7.7f};
  if (threat_type == "Password Spraying")
    return {Severity::High, 7.7f};
  if (threat_type == "Kerberoasting")
    return {Severity::High, 7.1f};

  // --- Denial of Service ---
  if (threat_type == "DNS Amplification")
    return {Severity::Critical, 9.2f};
  if (threat_type == "DDoS")
    return {Severity::High, 8.7f};
  if (threat_type == "Slowloris")
    return {Severity::High, 8.7f};
  if (threat_type == "HTTP Flood")
    return {Severity::High, 8.7f};
  if (threat_type == "ReDoS")
    return {Severity::High, 8.7f};

  // --- Reconnaissance / Enumeration ---
  if (threat_type == "Port Scan")
    return {Severity::Medium, 6.9f};
  if (threat_type == "Directory Enumeration")
    return {Severity::Medium, 6.9f};
  if (threat_type == "Version Fingerprinting")
    return {Severity::Medium, 6.9f};
  if (threat_type == "Vulnerability Scanning")
    return {Severity::Medium, 6.9f};
  if (threat_type == "User Enumeration")
    return {Severity::Medium, 6.9f};

  // --- Network / Protocol Attacks ---
  if (threat_type == "DNS Tunneling")
    return {Severity::High, 8.7f};
  if (threat_type == "DNS Poisoning")
    return {Severity::High, 8.3f};
  if (threat_type == "TLS Downgrade")
    return {Severity::High, 7.7f};
  if (threat_type == "SMTP Relay Abuse")
    return {Severity::Medium, 6.9f};
  if (threat_type == "DNS Rebinding")
    return {Severity::Medium, 6.0f};
  if (threat_type == "IP Spoofing")
    return {Severity::Medium, 5.3f};
  if (threat_type == "TCP Evasion")
    return {Severity::High, 7.5f}; // active IDS-evasion attempt

  // --- Encrypted-traffic (TLS metadata) ---
  if (threat_type == "Malicious TLS Client")
    return {Severity::High, 8.1f}; // known-malware JA3 fingerprint
  if (threat_type == "Suspicious TLS")
    return {Severity::Medium, 5.3f}; // DGA/raw-IP SNI

  // Unknown threat type — default to Medium
  return {Severity::Medium, 5.0f};
}

// Parse severity from LLM string output (case-insensitive).
// Uses CVSS 4.0 range midpoints when no specific score is known.
inline SeverityInfo severity_from_string(const std::string &s) {
  if (s == "Critical" || s == "critical") return {Severity::Critical, 9.5f};
  if (s == "High" || s == "high")         return {Severity::High, 8.0f};
  if (s == "Medium" || s == "medium")     return {Severity::Medium, 5.5f};
  if (s == "Low" || s == "low")           return {Severity::Low, 2.0f};
  return {Severity::Medium, 5.5f};
}

// Final severity for an LLM-classified alert. The curated severity_for_threat()
// table is the trusted CEILING for known attack types (SQLi is always High,
// etc.), but the LLM sees the actual payload, so it may DOWNGRADE a low-impact
// instance into Medium/Low (e.g. a recon probe, a deprecated-TLS handshake, an
// information leak). It may NEVER inflate a verdict — that stops an over-eager
// model from marking everything Critical. An empty or unrecognized severity
// token falls back to the curated rating. This downgrade path is what lets the
// Low tier actually populate (deterministic detectors are all Medium+).
inline SeverityInfo resolve_severity(const std::string &threat_type,
                                     const std::string &llm_severity) {
  SeverityInfo base = severity_for_threat(threat_type);
  std::string s; // ASCII-lowercase the token without pulling in <cctype>
  s.reserve(llm_severity.size());
  for (char c : llm_severity)
    s += static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
  Severity want;
  if (s == "critical")                              want = Severity::Critical;
  else if (s == "high")                             want = Severity::High;
  else if (s == "medium")                           want = Severity::Medium;
  else if (s == "low")                              want = Severity::Low;
  else if (s == "info" || s == "informational" ||
           s == "none")                             want = Severity::Info;
  else return base; // empty / unrecognized — trust the curated table
  // Honor only a downgrade (LLM tier strictly below the curated ceiling).
  if (static_cast<int>(want) < static_cast<int>(base.level)) {
    if (want == Severity::Info) return {Severity::Info, 0.0f};
    return severity_from_string(s);
  }
  return base;
}

enum class PipelineState { Stopped, Starting, Running, Stopping, Error };

struct PipelineStats {
  // Filter
  size_t filter_passed = 0;
  size_t filter_dropped = 0;
  size_t filter_deduped = 0;
  std::string filter_device; // "NPU", "CPU", or "Statistical"

  // LLM
  size_t alerts_fired = 0;

  // Queue depths (instantaneous)
  size_t queue_reassembly_to_filter_depth = 0;
  size_t queue_filter_to_llm_depth = 0;

  // Queue drops (cumulative)
  size_t queue_reassembly_to_filter_drops = 0;
  size_t queue_filter_to_llm_drops = 0;

  // Queue capacities
  size_t queue_reassembly_to_filter_capacity = 0;
  size_t queue_filter_to_llm_capacity = 0;

  // Offline capture status
  bool capture_finished = false;

  // IPS (inline blocking) — non-zero only in WinDivert inline mode
  size_t blocked_packets = 0; // total packets dropped from flagged sources
  size_t blocked_sources = 0; // distinct source IPs currently blocked
};

struct ThreatAlert {
  std::chrono::system_clock::time_point timestamp;
  ConnectionId connection;
  std::string threat_type;
  std::string severity;       // human-readable label (kept for backwards compat)
  SeverityInfo severity_info;  // structured severity with CVSS score
  std::string snippet;
  std::string raw_llm_output;
  std::string payload_text;
  float confidence = 0.0f;     // detection confidence (0..1); see confidence_for()
};

enum class FlowAction { Filtered, PassedToLLM, LLMCleared };

struct FlowEvent {
  std::chrono::system_clock::time_point timestamp;
  ConnectionId connection;
  FlowAction action;
  std::string reason;
  size_t payload_size = 0;
};

using OnThreatDetected = std::function<void(const ThreatAlert &)>;
using OnStatsUpdate = std::function<void(const PipelineStats &)>;
using OnStateChange = std::function<void(PipelineState)>;
using OnFlowEvent = std::function<void(const FlowEvent &)>;
