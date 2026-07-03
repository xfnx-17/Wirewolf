// probe.cpp — fast, LLM-free behavioral-detection probe.
//
// Runs ONLY capture -> TCP reassembly -> connection-level anomaly / beaconing
// detection on a labeled PCAP and scores per host pair. No NPU, no LLM, no
// model — so it finishes in seconds instead of the ~hour the full benchmark
// takes. Use it to iterate on behavioral C2 detection.
//
// Usage: wirewolf_probe <capture.pcap> <labels.csv>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#endif

#include "config.hpp"
#include "logger.hpp"
#include "packet_types.hpp"
#include "wirewolf_types.hpp"
#include "tcp_reassembly.hpp"
#include "thread_safe_queue.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>

namespace {
using PairKey = uint64_t;
PairKey make_pair_key(uint32_t a, uint32_t b) {
  uint32_t lo = std::min(a, b);
  uint32_t hi = std::max(a, b);
  return (static_cast<uint64_t>(lo) << 32) | hi;
}
uint32_t parse_ip(const std::string &s) {
  uint32_t ip = 0;
  unsigned o0;
  unsigned o1;
  unsigned o2;
  unsigned o3;
#ifdef _WIN32
  if (sscanf_s(s.c_str(), "%u.%u.%u.%u", &o0, &o1, &o2, &o3) == 4)
#else
  if (sscanf(s.c_str(), "%u.%u.%u.%u", &o0, &o1, &o2, &o3) == 4)
#endif
    ip = static_cast<uint32_t>(o0) | (o1 << 8) | (o2 << 16) | (o3 << 24);
  return ip;
}
std::string trim(const std::string &s) {
  size_t a = s.find_first_not_of(" \t\r\n");
  if (a == std::string::npos) return "";
  size_t b = s.find_last_not_of(" \t\r\n");
  return s.substr(a, b - a + 1);
}
} // namespace

int main(int argc, char *argv[]) {
  if (argc < 3) {
    std::cerr << "Usage: wirewolf_probe <capture.pcap> <labels.csv> "
                 "[behavioral_models_dir] [behavioral_threshold]\n";
    return 1;
  }
  const std::string pcap_path = argv[1];
  const std::string labels_path = argv[2];
  const std::string beh_dir = argc > 3 ? argv[3] : "";
  const double beh_thr = argc > 4 ? std::stod(argv[4]) : 0.0;
  Logger::instance().set_level(LogLevel::INFO);

  std::unordered_map<PairKey, std::string> labels;
  std::set<PairKey> malicious;
  std::set<PairKey> benign;
  {
    std::ifstream f(labels_path);
    if (!f) { std::cerr << "Cannot open labels: " << labels_path << "\n"; return 1; }
    std::string line;
    while (std::getline(f, line)) {
      line = trim(line);
      if (line.empty() || line[0] == '#') continue;
      std::stringstream ss(line);
      std::string a;
      std::string b;
      std::string label;
      std::getline(ss, a, ','); std::getline(ss, b, ','); std::getline(ss, label, ',');
      a = trim(a); b = trim(b); label = trim(label);
      if (a.empty() || b.empty()) continue;
      PairKey k = make_pair_key(parse_ip(a), parse_ip(b));
      std::string lc = label;
      std::transform(lc.begin(), lc.end(), lc.begin(), ::tolower);
      if (lc == "benign" || lc.empty()) benign.insert(k);
      else { malicious.insert(k); labels[k] = label; }
    }
  }
  std::cout << "Loaded labels: " << malicious.size() << " malicious, "
            << benign.size() << " benign pairs\n";

  std::set<PairKey> alerted;
  std::map<std::string, int> alert_types;

  WirewolfConfig cfg;
  cfg.interface = pcap_path; // offline (path ends in .pcap)
  cfg.use_windivert = false;
  cfg.analysis_mode = AnalysisMode::Forensic; // unscope behavioral (public IPs)
  cfg.threat_proxy_db = "flutter_app/assets/geo/proxy.bin"; // threat-intel
  cfg.behavioral_models_dir = beh_dir; // empty = behavioral scoring disabled
  cfg.behavioral_threshold = beh_thr;
  if (!beh_dir.empty())
    std::cout << "Behavioral models: " << beh_dir
              << " (threshold " << beh_thr << ", forensic mode)\n";

  ThreadSafeQueue<FlowPtr> q(4096);
  q.set_blocking(false); // discard flows; we only want connection-level alerts

  TcpReassembler reasm(cfg, q);
  reasm.set_on_threat_detected([&](const ThreatAlert &a) {
    alerted.insert(make_pair_key(a.connection.src_ip, a.connection.dst_ip));
    alert_types[a.threat_type]++;
  });

  std::cout << "Running behavioral detection on " << pcap_path << " ...\n";
  auto t0 = std::chrono::steady_clock::now();
  reasm.start(); // blocks until EOF + flush (offline)
  double secs = std::chrono::duration<double>(
                    std::chrono::steady_clock::now() - t0).count();

  int tp = 0;
  int fp = 0;
  int fn = 0;
  int tn = 0;
  std::map<std::string, std::pair<int, int>> per_type;
  for (PairKey k : malicious) {
    bool d = alerted.count(k) != 0;
    if (d) tp++; else fn++;
    auto &pt = per_type[labels[k]];
    pt.second++; if (d) pt.first++;
  }
  for (PairKey k : benign) { if (alerted.count(k)) fp++; else tn++; }

  auto div = [](double a, double b) { return b > 0 ? a / b : 0.0; };
  std::cout << "\n=========== BEHAVIORAL PROBE (no LLM) ===========\n";
  std::cout << "Processed in " << secs << "s\n";
  std::cout << "TP=" << tp << " FP=" << fp << " FN=" << fn << " TN=" << tn << "\n";
  printf("Precision %.3f  Recall %.3f  F1 %.3f\n",
         div(tp, tp + fp), div(tp, tp + fn),
         div(2.0 * tp, 2.0 * tp + fp + fn));
  std::cout << "\nPer-attack-type:\n";
  for (auto &[t, pr] : per_type)
    printf("  %-24s %d / %d\n", t.c_str(), pr.first, pr.second);
  std::cout << "\nAlerts raised by type:\n";
  for (auto &[t, n] : alert_types)
    printf("  %-24s %d\n", t.c_str(), n);
  std::cout << "=================================================\n";
  return 0;
}
