// ipscan.cpp — quick internal/external IP breakdown of a pcap.
// Usage: wirewolf_ipscan <capture.pcap>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#ifndef WPCAP
#define WPCAP
#endif
#ifndef HAVE_REMOTE
#define HAVE_REMOTE
#endif
#include <pcap.h>
#else
#include <pcap.h>
#endif

#include <cstdint>
#include <cstdio>
#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <vector>

static bool is_private(uint32_t net) { // network byte order
  const uint8_t *b = reinterpret_cast<const uint8_t *>(&net);
  return b[0] == 10 || b[0] == 127 || b[0] == 0 ||
         (b[0] == 172 && (b[1] & 0xF0) == 16) ||
         (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254);
}

int main(int argc, char **argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: wirewolf_ipscan <capture.pcap> [--pairs]\n");
    return 1;
  }
  // --pairs: emit every distinct host-pair as "src,dst" (one per line, direction-
  // normalized + deduped) so a benign-inclusive labels file can be generated for
  // false-positive benchmarking. Otherwise print the IP breakdown summary.
  const bool pairs_mode = (argc >= 3 && std::strcmp(argv[2], "--pairs") == 0);

  char err[PCAP_ERRBUF_SIZE];
  pcap_t *h = pcap_open_offline(argv[1], err);
  if (!h) {
    std::fprintf(stderr, "open failed: %s\n", err);
    return 1;
  }
  std::set<uint32_t> internal, external;
  std::map<uint32_t, long> ext_hits; // external IP -> packet count
  std::set<std::pair<uint32_t, uint32_t>> host_pairs; // normalized (lo,hi)
  long pkts = 0, ipv4 = 0;
  struct pcap_pkthdr *hdr;
  const u_char *data;
  int r;
  while ((r = pcap_next_ex(h, &hdr, &data)) >= 0) {
    if (r == 0) continue;
    ++pkts;
    if (hdr->caplen < 34) continue;
    if (((data[12] << 8) | data[13]) != 0x0800) continue; // IPv4 only
    const u_char *ip = data + 14;
    uint32_t src, dst;
    std::memcpy(&src, ip + 12, 4);
    std::memcpy(&dst, ip + 16, 4);
    ++ipv4;
    if (pairs_mode && src != dst)
      host_pairs.insert({std::min(src, dst), std::max(src, dst)});
    if (is_private(src)) internal.insert(src); else { external.insert(src); ext_hits[src]++; }
    if (is_private(dst)) internal.insert(dst); else { external.insert(dst); ext_hits[dst]++; }
  }
  pcap_close(h);

  if (pairs_mode) {
    auto p = [](uint32_t ip) {
      const uint8_t *b = reinterpret_cast<const uint8_t *>(&ip);
      std::printf("%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    };
    for (const auto &hp : host_pairs) {
      p(hp.first); std::printf(","); p(hp.second); std::printf("\n");
    }
    return 0;
  }

  std::printf("packets=%ld  ipv4=%ld\n", pkts, ipv4);
  std::printf("distinct INTERNAL (private) IPs: %zu\n", internal.size());
  std::printf("distinct EXTERNAL (public)  IPs: %zu\n", external.size());

  // top external IPs by packet volume
  std::vector<std::pair<long, uint32_t>> top;
  for (auto &kv : ext_hits) top.push_back({kv.second, kv.first});
  std::sort(top.rbegin(), top.rend());
  std::printf("top external IPs by packets:\n");
  for (size_t i = 0; i < top.size() && i < 15; ++i) {
    const uint8_t *b = reinterpret_cast<const uint8_t *>(&top[i].second);
    std::printf("  %3u.%u.%u.%u  %ld pkts\n", b[0], b[1], b[2], b[3], top[i].first);
  }
  return 0;
}
