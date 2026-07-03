#pragma once
// payload_normalizer.hpp — Anti-evasion canonicalization.
//
// Attackers obfuscate payloads so the same attack doesn't match a signature
// or read as malicious to the LLM:
//     ' OR 1=1--   →   %27%20OR%201%3D1--   →   %2527%2520OR...
//     <script>     →   %3Cscript%3E         →   <ScRiPt>
//     ;cat /etc/passwd  →  ;cat/**/​/etc/passwd
//
// normalize_payload() collapses these variants back to a canonical form so
// the signature filter and the LLM both see the real attack. It performs:
//   - recursive percent-decoding (%XX), catching double/triple encoding
//   - %uXXXX unicode decoding (low byte)
//   - whitespace collapse (tabs/newlines/runs of spaces -> single space)
//   - SQL comment stripping (/* ... */ and -- to end of line)
//   - lowercase folding
//
// The result is used ONLY for detection. The original raw bytes are preserved
// for verbatim snippet reporting.

#include <cstdint>
#include <string>
#include <vector>

inline int _hex_val(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Single percent-decoding pass. Decodes %XX and %uXXXX (low byte).
inline std::string _percent_decode_once(const std::string &in, bool &changed) {
  std::string out;
  out.reserve(in.size());
  changed = false;
  for (size_t i = 0; i < in.size(); ++i) {
    if (in[i] == '%' && i + 1 < in.size() && (in[i + 1] == 'u' || in[i + 1] == 'U')) {
      // %uXXXX — take the low byte
      if (i + 5 < in.size()) {
        int h1 = _hex_val(in[i + 4]);
        int h2 = _hex_val(in[i + 5]);
        if (h1 >= 0 && h2 >= 0) {
          out += static_cast<char>((h1 << 4) | h2);
          i += 5;
          changed = true;
          continue;
        }
      }
      out += in[i];
    } else if (in[i] == '%' && i + 2 < in.size()) {
      int h1 = _hex_val(in[i + 1]);
      int h2 = _hex_val(in[i + 2]);
      if (h1 >= 0 && h2 >= 0) {
        out += static_cast<char>((h1 << 4) | h2);
        i += 2;
        changed = true;
        continue;
      }
      out += in[i];
    } else if (in[i] == '+') {
      out += ' '; // form-encoding space
      changed = true;
    } else {
      out += in[i];
    }
  }
  return out;
}

inline std::string normalize_payload(const std::vector<uint8_t> &raw) {
  // Cap the work to avoid CPU DoS on huge payloads.
  static constexpr size_t MAX_NORM = 65536;
  size_t n = raw.size() < MAX_NORM ? raw.size() : MAX_NORM;
  std::string s(reinterpret_cast<const char *>(raw.data()), n);

  // Recursive percent-decode (catches double/triple encoding), depth-capped.
  for (int pass = 0; pass < 3; ++pass) {
    bool changed = false;
    s = _percent_decode_once(s, changed);
    if (!changed) break;
  }

  // Strip SQL comments and fold case + whitespace in one pass.
  std::string out;
  out.reserve(s.size());
  bool prev_space = false;
  for (size_t i = 0; i < s.size(); ++i) {
    // /* ... */ block comment
    if (s[i] == '/' && i + 1 < s.size() && s[i + 1] == '*') {
      size_t end = s.find("*/", i + 2);
      if (end == std::string::npos) break;
      i = end + 1;
      continue;
    }
    // -- line comment (SQL) and # comment
    if ((s[i] == '-' && i + 1 < s.size() && s[i + 1] == '-')) {
      size_t eol = s.find('\n', i);
      if (eol == std::string::npos) break;
      i = eol;
      continue;
    }
    char c = s[i];
    // collapse all whitespace to single space
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f') {
      if (!prev_space) {
        out += ' ';
        prev_space = true;
      }
      continue;
    }
    prev_space = false;
    // lowercase fold
    if (c >= 'A' && c <= 'Z')
      c = static_cast<char>(c - 'A' + 'a');
    out += c;
  }
  return out;
}
