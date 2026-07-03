#pragma once
// threat_feed.hpp — Updatable threat-intelligence / signature feed.
//
// Real IDS engines (Snort, Suricata) load detection rules from external files
// that can be refreshed from feeds (Emerging Threats, abuse.ch) without
// recompiling. This loads four rule types from a directory:
//
//   bad_ja3.txt      one JA3 MD5 hash per line              (malware TLS clients)
//   bad_domains.txt  one domain/substring per line          (C2 / phishing SNI+DNS)
//   bad_ips.txt      one IPv4 per line                      (known-bad endpoints)
//   signatures.txt   name|severity|substring  per line      (custom content sigs)
//
// Lines starting with '#' and blank lines are ignored. Reload at runtime via
// load(). Lookups are case-insensitive where it makes sense and O(1).

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

struct ContentSignature {
  std::string name;     // e.g. "ET MALWARE Generic Beacon"
  std::string severity; // threat_type used for CVSS lookup, e.g. "Malware Payload"
  std::string pattern;  // substring to match (lowercased)
};

class ThreatFeed {
public:
  // Load all rule files from dir. Missing files are skipped silently.
  // Returns total number of indicators loaded. Thread-unsafe; call before
  // starting the pipeline (or while stopped).
  size_t load(const std::string &dir) {
    bad_ja3_.clear();
    bad_domains_.clear();
    bad_ips_.clear();
    signatures_.clear();
    if (dir.empty())
      return 0;

    std::string base = dir;
    if (base.back() != '/' && base.back() != '\\')
      base += '/';

    load_set(base + "bad_ja3.txt", bad_ja3_, /*lower=*/true);
    load_set(base + "bad_domains.txt", bad_domains_, /*lower=*/true);
    load_set(base + "bad_ips.txt", bad_ips_, /*lower=*/false);
    load_signatures(base + "signatures.txt");

    loaded_dir_ = dir;
    return bad_ja3_.size() + bad_domains_.size() + bad_ips_.size() +
           signatures_.size();
  }

  bool empty() const {
    return bad_ja3_.empty() && bad_domains_.empty() && bad_ips_.empty() &&
           signatures_.empty();
  }

  size_t ja3_count() const { return bad_ja3_.size(); }
  size_t domain_count() const { return bad_domains_.size(); }
  size_t ip_count() const { return bad_ips_.size(); }
  size_t signature_count() const { return signatures_.size(); }

  bool is_bad_ja3(const std::string &ja3_hash) const {
    return bad_ja3_.count(to_lower(ja3_hash)) != 0;
  }

  // True if the SNI/hostname matches (exactly or as a parent domain of) any
  // blocked domain entry. "evil.com" matches "x.evil.com".
  bool is_bad_domain(const std::string &host) const {
    if (host.empty() || bad_domains_.empty())
      return false;
    std::string h = to_lower(host);
    if (bad_domains_.contains(h))
      return true;
    // suffix match on dot boundaries
    size_t pos = 0;
    while ((pos = h.find('.', pos)) != std::string::npos) {
      ++pos;
      if (bad_domains_.count(h.substr(pos)))
        return true;
    }
    return false;
  }

  // ip is a dotted string "1.2.3.4".
  bool is_bad_ip(const std::string &ip) const {
    return bad_ips_.contains(ip);
  }

  // Scan text (already lowercased recommended) for any content signature.
  // Returns pointer to the matched signature, or nullptr.
  const ContentSignature *match_signature(const std::string &text) const {
    for (const auto &sig : signatures_) {
      if (!sig.pattern.empty() && text.contains(sig.pattern))
        return &sig;
    }
    return nullptr;
  }

private:
  static std::string to_lower(const std::string &s) {
    std::string o = s;
    std::transform(o.begin(), o.end(), o.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return o;
  }

  static std::string trim(const std::string &s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos)
      return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
  }

  void load_set(const std::string &path, std::unordered_set<std::string> &out,
                bool lower) {
    std::ifstream f(path);
    if (!f)
      return;
    std::string line;
    while (std::getline(f, line)) {
      std::string v = trim(line);
      if (v.empty() || v[0] == '#')
        continue;
      out.insert(lower ? to_lower(v) : v);
    }
  }

  void load_signatures(const std::string &path) {
    std::ifstream f(path);
    if (!f)
      return;
    std::string line;
    while (std::getline(f, line)) {
      std::string v = trim(line);
      if (v.empty() || v[0] == '#')
        continue;
      // name|severity|pattern
      std::stringstream ss(v);
      ContentSignature sig;
      std::getline(ss, sig.name, '|');
      std::getline(ss, sig.severity, '|');
      std::getline(ss, sig.pattern);
      sig.name = trim(sig.name);
      sig.severity = trim(sig.severity);
      sig.pattern = to_lower(trim(sig.pattern));
      if (!sig.pattern.empty()) {
        if (sig.severity.empty())
          sig.severity = "Malware Payload";
        signatures_.push_back(std::move(sig));
      }
    }
  }

  std::unordered_set<std::string> bad_ja3_;
  std::unordered_set<std::string> bad_domains_;
  std::unordered_set<std::string> bad_ips_;
  std::vector<ContentSignature> signatures_;
  std::string loaded_dir_;
};
