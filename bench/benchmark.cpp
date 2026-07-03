// benchmark.cpp — Detection-efficacy harness for Wirewolf.
//
// Runs the full pipeline on a labeled PCAP and measures how well it actually
// detects, instead of relying on anecdote. Reports:
//   - End-to-end confusion matrix + precision / recall / F1 / accuracy
//   - Per-attack-type breakdown
//   - FILTER RECALL: of the malicious flows, how many the cheap pre-filter
//     forwarded to the LLM (vs silently dropped) — i.e. whether the LLM even
//     got a chance to see them.
//
// Usage:
//   wirewolf_bench <capture.pcap> <labels.csv> <llama_model.gguf> [--openvino m.xml]
//
// labels.csv format (one row per host pair, '#'=comment):
//   src_ip,dst_ip,label
//   10.0.0.50,192.168.1.5,SQLi
//   192.168.1.10,8.8.8.8,BENIGN
// label "BENIGN" (case-insensitive) = benign; anything else = malicious.
// Matching is direction-agnostic (the unordered {src,dst} pair is scored).

#include "bench_common.hpp"
#include "config.hpp"
#include "logger.hpp"
#include "pipeline_controller.hpp"
#include "wirewolf_types.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

using bench::make_pair_key;
using bench::parse_ip;
using bench::PairKey;
using bench::trim;

int main(int argc, char *argv[]) {
  if (argc < 4) {
    std::cerr << "Usage: wirewolf_bench <capture.pcap> <labels.csv> "
                 "<llama_model.gguf> [--openvino model.xml]\n";
    return 1;
  }
  const std::string pcap_path = argv[1];
  const std::string labels_path = argv[2];
  const std::string model_path = argv[3];

  Logger::instance().set_level(LogLevel::WARN); // keep benchmark output clean

  // ---- Load ground-truth labels ----
  std::unordered_map<PairKey, std::string> labels; // pair -> attack type
  std::set<PairKey> malicious;
  std::set<PairKey> benign;
  {
    std::ifstream f(labels_path);
    if (!f) {
      std::cerr << "Cannot open labels file: " << labels_path << "\n";
      return 1;
    }
    std::string line;
    while (std::getline(f, line)) {
      line = trim(line);
      if (line.empty() || line[0] == '#') continue;
      std::stringstream ss(line);
      std::string a;
      std::string b;
      std::string label;
      std::getline(ss, a, ',');
      std::getline(ss, b, ',');
      std::getline(ss, label, ',');
      a = trim(a); b = trim(b); label = trim(label);
      if (a.empty() || b.empty()) continue;
      PairKey k = make_pair_key(parse_ip(a), parse_ip(b));
      std::string lc = label;
      std::transform(lc.begin(), lc.end(), lc.begin(), ::tolower);
      if (lc == "benign" || lc.empty()) {
        benign.insert(k);
      } else {
        malicious.insert(k);
        labels[k] = label;
      }
    }
  }
  std::cout << "Loaded labels: " << malicious.size() << " malicious pairs, "
            << benign.size() << " benign pairs\n";
  if (malicious.empty() && benign.empty()) {
    std::cerr << "No usable labels.\n";
    return 1;
  }

  // ---- Collect results from the pipeline (thread-safe) ----
  std::mutex mtx;
  std::set<PairKey> alerted;                          // pairs that fired an alert
  std::map<std::string, int> alert_types;             // threat_type -> count
  std::unordered_map<PairKey, bool> mal_flow_reached; // malicious pair -> reached LLM?
  size_t total_flows = 0;
  size_t mal_flows = 0;
  size_t mal_flows_passed = 0;

  WirewolfConfig cfg;
  cfg.interface = pcap_path;          // offline mode (path ends in .pcap)
  cfg.llama_model_path = model_path;
  cfg.openvino_model_path = "";       // statistical filter by default
  for (int i = 4; i < argc; ++i) {
    if (std::string(argv[i]) == "--openvino" && i + 1 < argc) {
      cfg.openvino_model_path = argv[++i];
      cfg.openvino_enabled = true;
    }
  }
  if (cfg.openvino_model_path.empty())
    cfg.openvino_model_path = "none"; // satisfy validity when not used

  PipelineController controller;

  controller.set_on_threat_detected([&](const ThreatAlert &a) {
    std::scoped_lock lock(mtx);
    PairKey k = make_pair_key(a.connection.src_ip, a.connection.dst_ip);
    alerted.insert(k);
    alert_types[a.threat_type]++;
  });

  controller.set_on_flow_event([&](const FlowEvent &ev) {
    std::scoped_lock lock(mtx);
    total_flows++;
    PairKey k = make_pair_key(ev.connection.src_ip, ev.connection.dst_ip);
    if (malicious.contains(k)) {
      mal_flows++;
      // Reached the LLM if it was passed or later cleared by the LLM.
      if (ev.action == FlowAction::PassedToLLM ||
          ev.action == FlowAction::LLMCleared) {
        mal_flows_passed++;
        mal_flow_reached[k] = true;
      }
    }
  });

  std::cout << "Running pipeline on " << pcap_path << " ...\n";
  auto t0 = std::chrono::steady_clock::now();
  if (!controller.start(cfg)) {
    std::cerr << "Failed to start pipeline: " << controller.last_error() << "\n";
    return 1;
  }
  // Offline mode auto-stops when the capture is fully processed.
  while (controller.state() == PipelineState::Starting ||
         controller.state() == PipelineState::Running) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
  auto t1 = std::chrono::steady_clock::now();
  double secs = std::chrono::duration<double>(t1 - t0).count();

  if (controller.state() == PipelineState::Error) {
    std::cerr << "Pipeline error: " << controller.last_error() << "\n";
    return 1;
  }

  // ---- Score ----
  int tp = 0;
  int fp = 0;
  int fn = 0;
  int tn = 0;
  std::map<std::string, std::pair<int, int>> per_type; // type -> {detected, total}

  for (PairKey k : malicious) {
    bool detected = alerted.contains(k);
    if (detected) tp++; else fn++;
    auto &pt = per_type[labels[k]];
    pt.second++;
    if (detected) pt.first++;
  }
  for (PairKey k : benign) {
    if (alerted.contains(k)) fp++; else tn++;
  }

  auto div = [](double a, double b) { return b > 0 ? a / b : 0.0; };
  double precision = div(tp, tp + fp);
  double recall = div(tp, tp + fn);
  double f1 = div(2 * precision * recall, precision + recall);
  double accuracy = div(tp + tn, tp + tn + fp + fn);
  double filter_recall = div(mal_flows_passed, mal_flows);

  // ---- Report ----
  std::cout << "\n==================== BENCHMARK RESULTS ====================\n";
  std::cout << "Processed in " << secs << "s, " << total_flows
            << " flow events observed\n\n";
  std::cout << "Confusion matrix (per host pair):\n";
  std::cout << "  TP=" << tp << "  FP=" << fp << "  FN=" << fn << "  TN=" << tn
            << "\n\n";
  printf("  Precision : %.3f\n", precision);
  printf("  Recall    : %.3f\n", recall);
  printf("  F1 score  : %.3f\n", f1);
  printf("  Accuracy  : %.3f\n", accuracy);

  std::cout << "\nFilter recall (did malicious flows reach the LLM?):\n";
  printf("  %zu / %zu malicious flows passed the pre-filter = %.3f\n",
         mal_flows_passed, mal_flows, filter_recall);
  if (filter_recall < 0.95 && mal_flows > 0)
    std::cout << "  WARNING: the pre-filter dropped some malicious flows "
                 "before the LLM saw them.\n";

  std::cout << "\nPer-attack-type detection:\n";
  for (const auto &[type, pr] : per_type)
    printf("  %-24s %d / %d  (%.0f%%)\n", type.c_str(), pr.first, pr.second,
           100.0 * div(pr.first, pr.second));

  std::cout << "\nAlerts raised by type:\n";
  for (const auto &[type, n] : alert_types)
    printf("  %-24s %d\n", type.c_str(), n);
  std::cout << "===========================================================\n";

  return 0;
}
