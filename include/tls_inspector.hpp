#pragma once
// tls_inspector.hpp — Encrypted-traffic analysis WITHOUT decryption.
//
// The TLS handshake leaks metadata in cleartext before encryption begins.
// This parses a TLS ClientHello (already sitting in the reassembled payload)
// and extracts:
//   - SNI (Server Name Indication): the destination hostname, even over HTTPS
//   - JA3 fingerprint: an MD5 of the ClientHello shape (version, ciphers,
//     extensions, curves, point formats) that identifies the client app /
//     malware family. This is exactly what Zeek/Suricata do.
//
// No MITM, no installed certificates, no plaintext — just the handshake.

#include <array>
#include <cstdint>
#include <string>
#include <vector>

struct TlsInfo {
  bool is_client_hello = false;
  std::string sni;       // e.g. "example.com"  (empty if absent)
  std::string ja3;       // raw JA3 string (decimal fields)
  std::string ja3_hash;  // 32-char MD5 hex of ja3
};

// ---------------- compact MD5 (public-domain style) ----------------
namespace _md5 {
struct Ctx {
  uint32_t a, b, c, d;
  uint64_t len;
  uint8_t buf[64];
  size_t buflen;
};
inline uint32_t rol(uint32_t x, int s) { return (x << s) | (x >> (32 - s)); }

inline void process(Ctx &ctx, const uint8_t *p) {
  static const uint32_t K[64] = {
      0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,
      0xa8304613,0xfd469501,0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
      0x6b901122,0xfd987193,0xa679438e,0x49b40821,0xf61e2562,0xc040b340,
      0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
      0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,
      0x676f02d9,0x8d2a4c8a,0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
      0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,0x289b7ec6,0xeaa127fa,
      0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
      0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,
      0xffeff47d,0x85845dd1,0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
      0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};
  static const int S[64] = {7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
                            5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
                            4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
                            6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};
  uint32_t M[16];
  for (int i = 0; i < 16; ++i)
    M[i] = p[i*4] | (p[i*4+1] << 8) | (p[i*4+2] << 16) | ((uint32_t)p[i*4+3] << 24);
  uint32_t A = ctx.a, B = ctx.b, C = ctx.c, D = ctx.d;
  for (int i = 0; i < 64; ++i) {
    uint32_t F; int g;
    if (i < 16)      { F = (B & C) | (~B & D); g = i; }
    else if (i < 32) { F = (D & B) | (~D & C); g = (5*i + 1) & 15; }
    else if (i < 48) { F = B ^ C ^ D;          g = (3*i + 5) & 15; }
    else             { F = C ^ (B | ~D);       g = (7*i) & 15; }
    F = F + A + K[i] + M[g];
    A = D; D = C; C = B; B = B + rol(F, S[i]);
  }
  ctx.a += A; ctx.b += B; ctx.c += C; ctx.d += D;
}

inline std::string hash(const std::string &in) {
  Ctx ctx{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0, {}, 0};
  ctx.len = in.size();
  const uint8_t *data = reinterpret_cast<const uint8_t *>(in.data());
  size_t n = in.size();
  size_t off = 0;
  while (n - off >= 64) { process(ctx, data + off); off += 64; }
  uint8_t tail[128];
  size_t rem = n - off;
  for (size_t i = 0; i < rem; ++i) tail[i] = data[off + i];
  tail[rem] = 0x80;
  size_t padlen = (rem < 56) ? (56 - rem) : (120 - rem);
  for (size_t i = 1; i < padlen; ++i) tail[rem + i] = 0;
  uint64_t bits = ctx.len * 8;
  for (int i = 0; i < 8; ++i) tail[rem + padlen + i] = (uint8_t)(bits >> (8*i));
  size_t total = rem + padlen + 8;
  for (size_t i = 0; i < total; i += 64) process(ctx, tail + i);
  uint8_t out[16];
  uint32_t v[4] = {ctx.a, ctx.b, ctx.c, ctx.d};
  for (int i = 0; i < 4; ++i)
    for (int j = 0; j < 4; ++j) out[i*4 + j] = (uint8_t)(v[i] >> (8*j));
  static const char *hex = "0123456789abcdef";
  std::string s;
  s.reserve(32);
  for (int i = 0; i < 16; ++i) { s += hex[out[i] >> 4]; s += hex[out[i] & 15]; }
  return s;
}
} // namespace _md5

// GREASE values (RFC 8701) must be excluded from JA3.
inline bool _is_grease(uint16_t v) {
  return (v & 0x0f0f) == 0x0a0a;
}

// Parse a TLS ClientHello out of a reassembled TCP payload.
// Returns true if a ClientHello was found and parsed.
inline bool parse_tls_client_hello(const std::vector<uint8_t> &p, TlsInfo &out) {
  // TLS record: type(1)=0x16 handshake, version(2), length(2)
  if (p.size() < 6 || p[0] != 0x16)
    return false;
  size_t pos = 5; // start of handshake
  if (pos + 4 > p.size())
    return false;
  if (p[pos] != 0x01) // handshake type 1 = ClientHello
    return false;
  // handshake length (3 bytes) — skip
  pos += 4;
  if (pos + 2 > p.size())
    return false;

  uint16_t client_version = (p[pos] << 8) | p[pos + 1];
  pos += 2;
  pos += 32; // random
  if (pos >= p.size())
    return false;
  uint8_t sid_len = p[pos];
  pos += 1 + sid_len;
  if (pos + 2 > p.size())
    return false;

  // Cipher suites
  uint16_t cs_len = (p[pos] << 8) | p[pos + 1];
  pos += 2;
  if (pos + cs_len > p.size())
    return false;
  std::vector<uint16_t> ciphers;
  for (uint16_t i = 0; i + 1 < cs_len; i += 2) {
    uint16_t c = (p[pos + i] << 8) | p[pos + i + 1];
    if (!_is_grease(c)) ciphers.push_back(c);
  }
  pos += cs_len;
  if (pos >= p.size())
    return false;

  // Compression methods
  uint8_t comp_len = p[pos];
  pos += 1 + comp_len;
  if (pos + 2 > p.size()) {
    // No extensions — still a valid ClientHello
    out.is_client_hello = true;
    return true;
  }

  // Extensions
  uint16_t ext_total = (p[pos] << 8) | p[pos + 1];
  pos += 2;
  size_t ext_end = pos + ext_total;
  if (ext_end > p.size()) ext_end = p.size();

  std::vector<uint16_t> extensions, curves, formats;
  while (pos + 4 <= ext_end) {
    uint16_t etype = (p[pos] << 8) | p[pos + 1];
    uint16_t elen = (p[pos + 2] << 8) | p[pos + 3];
    pos += 4;
    if (pos + elen > ext_end) break;
    if (!_is_grease(etype)) extensions.push_back(etype);

    if (etype == 0x0000 && elen >= 5) {
      // SNI extension: server_name_list(2) + type(1)=0 + name_len(2) + name
      size_t sp = pos + 2 + 1;
      if (sp + 2 <= pos + elen) {
        uint16_t name_len = (p[sp] << 8) | p[sp + 1];
        sp += 2;
        if (sp + name_len <= pos + elen)
          out.sni.assign(reinterpret_cast<const char *>(&p[sp]), name_len);
      }
    } else if (etype == 0x000a) {
      // supported_groups (elliptic curves)
      if (elen >= 2) {
        uint16_t list_len = (p[pos] << 8) | p[pos + 1];
        for (uint16_t i = 0; i + 1 < list_len && pos + 2 + i + 1 < pos + elen; i += 2) {
          uint16_t c = (p[pos + 2 + i] << 8) | p[pos + 2 + i + 1];
          if (!_is_grease(c)) curves.push_back(c);
        }
      }
    } else if (etype == 0x000b) {
      // ec_point_formats
      if (elen >= 1) {
        uint8_t list_len = p[pos];
        for (uint8_t i = 0; i < list_len && pos + 1 + i < pos + elen; ++i)
          formats.push_back(p[pos + 1 + i]);
      }
    }
    pos += elen;
  }

  // Build the JA3 string: ver,ciphers,exts,curves,formats (decimal, '-' joined)
  auto join = [](const std::vector<uint16_t> &v) {
    std::string s;
    for (size_t i = 0; i < v.size(); ++i) {
      if (i) s += '-';
      s += std::to_string(v[i]);
    }
    return s;
  };
  out.ja3 = std::to_string(client_version) + "," + join(ciphers) + "," +
            join(extensions) + "," + join(curves) + "," + join(formats);
  out.ja3_hash = _md5::hash(out.ja3);
  out.is_client_hello = true;
  return true;
}
