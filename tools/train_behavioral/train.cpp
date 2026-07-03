// train_behavioral — offline trainer for the behavioral C2 Markov models.
//
// Pipeline:  .binetflow  ->  connections (per 4-tuple)  ->  state strings
//            (behavioral::encode_connection)  ->  per-class MarkovModels
//            ->  models/  +  holdout evaluation (precision/recall/F1).
//
// Clean-room: models are built from OUR encoder run over the public CTU-13
// labeled flows. No Stratosphere/Slips code or trained models are used.
//
// Usage:
//   train_behavioral --train a.binetflow[,b.binetflow...] \
//                     --test  c.binetflow[,d.binetflow...] \
//                     [--out-dir models] [--label-rule any|majority] \
//                     [--min-flows N] [--k K] [--threshold T] \
//                     [--include-background]
//
// Train and test files MUST be different scenarios (holdout) for a credible
// result.

#define _CRT_SECURE_NO_WARNINGS // std::sscanf on MSVC
#include "behavioral_model.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

using behavioral::BehavioralConfig;
using behavioral::Flow;
using behavioral::MarkovModel;

enum class Cls { Botnet, Normal, Background, Other };

struct ConnAcc {
  std::vector<Flow> flows;
  int botnet = 0;
  int normal = 0;
  int background = 0;
  int total = 0;
};

// ---- helpers ----
static std::vector<std::string> split(const std::string &s, char d) {
  std::vector<std::string> out;
  std::string cur;
  std::istringstream ss(s);
  while (std::getline(ss, cur, d)) out.push_back(cur);
  return out;
}
static std::string lower(std::string s) {
  for (auto &c : s) c = static_cast<char>(::tolower((unsigned char)c));
  return s;
}

// days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
static long days_from_civil(int y, unsigned m, unsigned d) {
  y -= m <= 2;
  long era = (y >= 0 ? y : y - 399) / 400;
  unsigned yoe = (unsigned)(y - era * 400);
  unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097L + (long)doe - 719468L;
}

// Parse "YYYY/MM/DD HH:MM:SS.ffffff" (CTU-13 binetflow) → epoch seconds.
static double parse_time(const std::string &t) {
  int Y = 0;
  int Mo = 0;
  int D = 0;
  int H = 0;
  int Mi = 0;
  double S = 0;
  if (std::sscanf(t.c_str(), "%d/%d/%d %d:%d:%lf", &Y, &Mo, &D, &H, &Mi, &S) < 6)
    return 0.0;
  long days = days_from_civil(Y, (unsigned)Mo, (unsigned)D);
  return (double)days * 86400.0 + H * 3600.0 + Mi * 60.0 + S;
}

static Cls classify(const std::string &label) {
  std::string l = lower(label);
  if (l.contains("botnet")) return Cls::Botnet;
  if (l.contains("normal")) return Cls::Normal;
  if (l.contains("background")) return Cls::Background;
  return Cls::Other;
}

// Read one .binetflow into the connection map (header maps columns by name).
static bool read_binetflow(const std::string &path,
                           std::map<std::string, ConnAcc> &conns, long &rows_ok,
                           long &rows_bad) {
  std::ifstream f(path);
  if (!f) {
    std::cerr << "Cannot open " << path << "\n";
    return false;
  }
  std::string header;
  if (!std::getline(f, header)) return false;
  std::map<std::string, int> col;
  {
    auto h = split(header, ',');
    for (int i = 0; i < (int)h.size(); ++i) col[h[i]] = i;
  }
  auto need = [&](const char *n) { return col.contains(n) ? col[n] : -1; };
  int ci_start = need("StartTime");
  int ci_dur = need("Dur");
  int ci_proto = need("Proto");
  int ci_src = need("SrcAddr");
  int ci_dst = need("DstAddr");
  int ci_dport = need("Dport");
  int ci_bytes = need("TotBytes");
  int ci_label = need("Label");
  if (ci_start < 0 || ci_dur < 0 || ci_proto < 0 || ci_src < 0 || ci_dst < 0 ||
      ci_dport < 0 || ci_bytes < 0 || ci_label < 0) {
    std::cerr << "Missing required columns in " << path << "\n";
    return false;
  }
  std::string line;
  while (std::getline(f, line)) {
    if (line.empty()) continue;
    auto c = split(line, ',');
    int maxc = std::max({ci_start, ci_dur, ci_proto, ci_src, ci_dst, ci_dport,
                         ci_bytes, ci_label});
    if ((int)c.size() <= maxc) { ++rows_bad; continue; }
    try {
      Flow fl;
      fl.start_time = parse_time(c[ci_start]);
      fl.duration = c[ci_dur].empty() ? 0.0 : std::stod(c[ci_dur]);
      fl.tot_bytes = c[ci_bytes].empty() ? 0 : (uint64_t)std::stoull(c[ci_bytes]);
      std::string key = c[ci_src] + "|" + c[ci_dst] + "|" + c[ci_dport] + "|" +
                        lower(c[ci_proto]);
      auto &a = conns[key];
      a.flows.push_back(fl);
      ++a.total;
      switch (classify(c[ci_label])) {
        case Cls::Botnet: ++a.botnet; break;
        case Cls::Normal: ++a.normal; break;
        case Cls::Background: ++a.background; break;
        default: break;
      }
      ++rows_ok;
    } catch (...) { ++rows_bad; }
  }
  return true;
}

// Decide a connection's class from its flows.
static Cls conn_label(const ConnAcc &a, bool majority) {
  if (majority) {
    if (a.botnet * 2 > a.total) return Cls::Botnet;
    if (a.normal >= a.background) return Cls::Normal;
    return Cls::Background;
  }
  if (a.botnet > 0) return Cls::Botnet; // "any"
  if (a.normal > 0) return Cls::Normal;
  return Cls::Background;
}

struct Args {
  std::vector<std::string> train;
  std::vector<std::string> test;
  // train-on-pcap mode: state strings (from export_states) + binetflow labels.
  std::vector<std::string> train_states;
  std::vector<std::string> train_bf;
  std::vector<std::string> test_states;
  std::vector<std::string> test_bf;
  std::string out_dir = "models";
  bool majority = false;
  bool include_bg = false;
  size_t min_flows = 4;
  double k = 0.5;
  double threshold = 0.0;
};

// ---- train-on-pcap (state strings + binetflow labels) helpers ----
static uint32_t parse_ip4(const std::string &s) {
  uint32_t a = 0;
  uint32_t b = 0;
  uint32_t c = 0;
  uint32_t d = 0;
  if (std::sscanf(s.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
    return 0;
  return (a << 24) | (b << 16) | (c << 8) | d;
}
static int parse_port(const std::string &s) {
  try {
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
      return (int)std::stol(s, nullptr, 16);
    return std::stoi(s);
  } catch (...) {
    return -1;
  }
}
// Order-independent 4-tuple key: {min,max} IP pair + dport.
static std::string tuple_key(const std::string &a, const std::string &b,
                             int dport) {
  uint32_t ia = parse_ip4(a);
  uint32_t ib = parse_ip4(b);
  uint32_t lo = std::min(ia, ib);
  uint32_t hi = std::max(ia, ib);
  return std::to_string(lo) + "-" + std::to_string(hi) + "-" +
         std::to_string(dport);
}

struct LblCount {
  int bot = 0;
  int norm = 0;
  int bg = 0;
};

// Build a 4-tuple -> class-count map from binetflow label files.
static void load_bf_labels(const std::string &path,
                           std::map<std::string, LblCount> &m, long &rows) {
  std::ifstream f(path);
  if (!f) {
    std::cerr << "Cannot open binetflow: " << path << "\n";
    return;
  }
  std::string header;
  if (!std::getline(f, header))
    return;
  std::map<std::string, int> col;
  {
    auto h = split(header, ',');
    for (int i = 0; i < (int)h.size(); ++i)
      col[h[i]] = i;
  }
  auto need = [&](const char *n) { return col.contains(n) ? col[n] : -1; };
  int ci_src = need("SrcAddr");
  int ci_dst = need("DstAddr");
  int ci_dport = need("Dport");
  int ci_label = need("Label");
  if (ci_src < 0 || ci_dst < 0 || ci_dport < 0 || ci_label < 0) {
    std::cerr << "Missing columns in " << path << "\n";
    return;
  }
  int maxc = std::max({ci_src, ci_dst, ci_dport, ci_label});
  std::string line;
  while (std::getline(f, line)) {
    if (line.empty())
      continue;
    auto c = split(line, ',');
    if ((int)c.size() <= maxc)
      continue;
    int dport = parse_port(c[ci_dport]);
    if (dport < 0)
      continue;
    std::string k = tuple_key(c[ci_src], c[ci_dst], dport);
    auto &lc = m[k];
    switch (classify(c[ci_label])) {
      case Cls::Botnet: ++lc.bot; break;
      case Cls::Normal: ++lc.norm; break;
      case Cls::Background: ++lc.bg; break;
      default: break;
    }
    ++rows;
  }
}

static Cls key_label(const LblCount &c, bool majority) {
  if (majority) {
    int tot = c.bot + c.norm + c.bg;
    if (c.bot * 2 > tot) return Cls::Botnet;
    if (c.norm >= c.bg) return Cls::Normal;
    return Cls::Background;
  }
  if (c.bot > 0) return Cls::Botnet;
  if (c.norm > 0) return Cls::Normal;
  return Cls::Background;
}

// Read state CSV (src,dst,dport,state from export_states) and label each row
// by joining its 4-tuple to the binetflow label map. Appends (state, isBot)
// to samples; trains the models if bot/norm are provided.
static void process_states(const std::vector<std::string> &state_files,
                           const std::map<std::string, LblCount> &labels,
                           bool majority, bool include_bg, MarkovModel *bot,
                           MarkovModel *norm,
                           std::vector<std::pair<std::string, bool>> *samples,
                           long &kept, long &unlabeled) {
  for (const auto &sf : state_files) {
    std::ifstream f(sf);
    if (!f) { std::cerr << "Cannot open states: " << sf << "\n"; continue; }
    std::string line;
    std::getline(f, line); // header
    while (std::getline(f, line)) {
      if (line.empty()) continue;
      auto c = split(line, ',');
      if (c.size() < 4) continue;
      int dport = parse_port(c[2]);
      const std::string &state = c[3];
      if (state.size() < 2) continue;
      auto it = labels.find(tuple_key(c[0], c[1], dport));
      if (it == labels.end()) { ++unlabeled; continue; }
      Cls cl = key_label(it->second, majority);
      bool isBot;
      if (cl == Cls::Botnet) isBot = true;
      else if (cl == Cls::Normal || (include_bg && cl == Cls::Background)) isBot = false;
      else continue; // skip Background unless included
      ++kept;
      if (bot && norm) (isBot ? *bot : *norm).observe(state);
      if (samples) samples->push_back({state, isBot});
    }
  }
}

static int run_states_mode(const Args &A);

static void add_paths(std::vector<std::string> &v, const std::string &csv) {
  for (const auto &p : split(csv, ',')) if (!p.empty()) v.push_back(p);
}

int main(int argc, char **argv) {
  Args A;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    auto next = [&]() { return i + 1 < argc ? argv[++i] : ""; };
    if (a == "--train") add_paths(A.train, next());
    else if (a == "--test") add_paths(A.test, next());
    else if (a == "--out-dir") A.out_dir = next();
    else if (a == "--label-rule") A.majority = (std::string(next()) == "majority");
    else if (a == "--min-flows") A.min_flows = std::stoul(next());
    else if (a == "--k") A.k = std::stod(next());
    else if (a == "--threshold") A.threshold = std::stod(next());
    else if (a == "--include-background") A.include_bg = true;
    else if (a == "--train-states") add_paths(A.train_states, next());
    else if (a == "--train-binetflow") add_paths(A.train_bf, next());
    else if (a == "--test-states") add_paths(A.test_states, next());
    else if (a == "--test-binetflow") add_paths(A.test_bf, next());
    else { std::cerr << "Unknown arg: " << a << "\n"; return 1; }
  }

  // Train-on-pcap mode: state strings (export_states) + binetflow labels.
  if (!A.train_states.empty())
    return run_states_mode(A);

  if (A.train.empty()) {
    std::cerr << "Usage: train_behavioral --train <files> --test <files> [opts]\n"
                 "   or: train_behavioral --train-states <csv> --train-binetflow"
                 " <bf> --test-states <csv> --test-binetflow <bf> [opts]\n";
    return 1;
  }

  // Ensure the output directory exists (create nested dirs if needed).
  std::error_code ec;
  std::filesystem::create_directories(A.out_dir, ec);

  BehavioralConfig cfg;
  cfg.markov_k = A.k;
  cfg.min_flows = A.min_flows;
  const std::string cfg_fp = cfg.fingerprint(); // renamed: 'fp' is the FP counter below

  // ---- TRAIN ----
  std::map<std::string, ConnAcc> train_conns;
  long rok = 0;
  long rbad = 0;
  for (const auto &p : A.train) read_binetflow(p, train_conns, rok, rbad);
  std::cout << "Train: read " << rok << " flow rows (" << rbad << " skipped) over "
            << train_conns.size() << " connections\n";

  MarkovModel botnet("Botnet", A.k);
  MarkovModel normal("Normal", A.k);
  long n_bot = 0;
  long n_norm = 0;
  double len_bot = 0;
  double len_norm = 0;
  std::vector<std::string> ex_bot;
  std::vector<std::string> ex_norm;
  for (const auto &kv : train_conns) {
    if (kv.second.flows.size() < A.min_flows) continue;
    std::string s = behavioral::encode_connection(kv.second.flows, cfg);
    if (s.size() < 2) continue;
    Cls c = conn_label(kv.second, A.majority);
    if (c == Cls::Botnet) {
      botnet.observe(s); ++n_bot; len_bot += s.size();
      if (ex_bot.size() < 3) ex_bot.push_back(s.substr(0, 40));
    } else if (c == Cls::Normal || (A.include_bg && c == Cls::Background)) {
      normal.observe(s); ++n_norm; len_norm += s.size();
      if (ex_norm.size() < 3) ex_norm.push_back(s.substr(0, 40));
    }
  }

  // ---- serialize models ----
  auto write_model = [&](const MarkovModel &m, const std::string &name) {
    std::string path = A.out_dir + "/" + name;
    std::ofstream os(path);
    if (!os) { std::cerr << "Cannot write " << path << "\n"; return; }
    m.serialize(os, cfg_fp);
    std::cout << "Wrote " << path << "\n";
  };
  write_model(botnet, "behavioral.botnet.model");
  write_model(normal, "behavioral.normal.model");

  // ---- training report ----
  std::cout << "\n=== TRAINING REPORT ===\n";
  std::cout << "Config fingerprint: " << cfg_fp << "\n";
  std::cout << "Botnet connections: " << n_bot
            << " (avg len " << (n_bot ? len_bot / n_bot : 0) << ", alphabet "
            << botnet.alphabet_size() << ")\n";
  std::cout << "Normal connections: " << n_norm
            << " (avg len " << (n_norm ? len_norm / n_norm : 0) << ", alphabet "
            << normal.alphabet_size() << ")\n";
  std::cout << "Example Botnet strings:\n";
  for (const auto &s : ex_bot) std::cout << "  " << s << "\n";
  std::cout << "Example Normal strings:\n";
  for (const auto &s : ex_norm) std::cout << "  " << s << "\n";

  if (A.test.empty()) {
    std::cout << "\nNo --test scenarios given; skipping evaluation.\n";
    return 0;
  }

  // ---- EVALUATE on held-out scenarios ----
  std::map<std::string, ConnAcc> test_conns;
  long trok = 0;
  long trbad = 0;
  for (const auto &p : A.test) read_binetflow(p, test_conns, trok, trbad);

  struct Sample { double llr; bool is_botnet; };
  std::vector<Sample> samples;
  for (const auto &kv : test_conns) {
    if (kv.second.flows.size() < A.min_flows) continue;
    std::string s = behavioral::encode_connection(kv.second.flows, cfg);
    if (s.size() < 2) continue;
    Cls c = conn_label(kv.second, A.majority);
    bool is_bot;
    if (c == Cls::Botnet) is_bot = true;
    else if (c == Cls::Normal || (A.include_bg && c == Cls::Background)) is_bot = false;
    else continue; // skip Background unless included
    samples.push_back({botnet.score(s) - normal.score(s), is_bot});
  }
  std::cout << "\nTest: " << samples.size() << " labeled connections held out\n";

  auto confusion = [&](double thr, long &tp, long &fp, long &fn, long &tn) {
    tp = fp = fn = tn = 0;
    for (const auto &s : samples) {
      bool pred = s.llr > thr;
      if (s.is_botnet) (pred ? tp : fn)++;
      else (pred ? fp : tn)++;
    }
  };
  auto prf = [](long tp, long fp, long fn) {
    double p = (tp + fp) ? (double)tp / (tp + fp) : 0;
    double r = (tp + fn) ? (double)tp / (tp + fn) : 0;
    double f = (p + r) ? 2 * p * r / (p + r) : 0;
    return std::tuple<double, double, double>(p, r, f);
  };

  // threshold sweep CSV
  std::string csv_path = A.out_dir + "/behavioral_eval.csv";
  std::ofstream csv(csv_path);
  csv << "threshold,TP,FP,FN,TN,precision,recall,f1\n";
  for (int sweep = 0; sweep <= 24; ++sweep) {
    const double t = -3.0 + 0.25 * sweep;
    long tp;
    long fp;
    long fn;
    long tn;
    confusion(t, tp, fp, fn, tn);
    auto [p, r, fsc] = prf(tp, fp, fn);
    csv << t << "," << tp << "," << fp << "," << fn << "," << tn << "," << p
        << "," << r << "," << fsc << "\n";
  }
  csv.close();

  long tp;
  long fp;
  long fn;
  long tn;
  confusion(A.threshold, tp, fp, fn, tn);
  auto [p, r, fsc] = prf(tp, fp, fn);
  std::cout << "\n=== EVALUATION (Botnet detection, threshold " << A.threshold
            << ") ===\n";
  std::cout << "Confusion: TP=" << tp << " FP=" << fp << " FN=" << fn
            << " TN=" << tn << "\n";
  printf("Precision %.3f  Recall %.3f  F1 %.3f\n", p, r, fsc);
  std::cout << "Threshold sweep written to " << csv_path << "\n";
  std::cout << "Note: raising --threshold increases precision (fewer false "
               "alarms) at the cost of recall; lowering it does the reverse. "
               "Pick an operating point from the sweep CSV.\n";

  // small JSON summary
  std::ofstream js(A.out_dir + "/behavioral_report.json");
  js << "{\n  \"config_fingerprint\": \"" << cfg_fp << "\",\n"
     << "  \"train_connections\": {\"botnet\": " << n_bot << ", \"normal\": "
     << n_norm << "},\n"
     << "  \"test_labeled\": " << samples.size() << ",\n"
     << "  \"threshold\": " << A.threshold << ",\n"
     << "  \"confusion\": {\"tp\": " << tp << ", \"fp\": " << fp << ", \"fn\": "
     << fn << ", \"tn\": " << tn << "},\n"
     << "  \"precision\": " << p << ", \"recall\": " << r << ", \"f1\": " << fsc
     << "\n}\n";
  return 0;
}

// ---- train-on-pcap mode: engine-extracted state strings + binetflow labels ----
static int run_states_mode(const Args &A) {
  std::error_code ec;
  std::filesystem::create_directories(A.out_dir, ec);
  BehavioralConfig cfg;
  cfg.markov_k = A.k;
  cfg.min_flows = A.min_flows;
  const std::string cfg_fp = cfg.fingerprint();

  // TRAIN: load labels from binetflow, train on engine-exported state strings.
  std::map<std::string, LblCount> trainLbl;
  long bfrows = 0;
  for (auto &p : A.train_bf) load_bf_labels(p, trainLbl, bfrows);
  std::cout << "Train: " << A.train_bf.size() << " binetflow file(s), "
            << trainLbl.size() << " labeled 4-tuples\n";

  MarkovModel bot("Botnet", A.k);
  MarkovModel norm("Normal", A.k);
  long kept = 0;
  long unlbl = 0;
  process_states(A.train_states, trainLbl, A.majority, A.include_bg, &bot, &norm,
                 nullptr, kept, unlbl);
  std::cout << "Train: " << kept << " labeled connections (" << unlbl
            << " unlabeled skipped)\n";

  auto write_model = [&](const MarkovModel &m, const std::string &name) {
    std::ofstream os(A.out_dir + "/" + name);
    if (os) {
      m.serialize(os, cfg_fp);
      std::cout << "Wrote " << A.out_dir << "/" << name << "\n";
    }
  };
  write_model(bot, "behavioral.botnet.model");
  write_model(norm, "behavioral.normal.model");

  std::cout << "\n=== TRAINING REPORT (train-on-pcap) ===\n";
  std::cout << "Config fingerprint: " << cfg_fp << "\n";
  std::cout << "Botnet alphabet " << bot.alphabet_size() << ", Normal alphabet "
            << norm.alphabet_size() << "\n";

  if (A.test_states.empty()) {
    std::cout << "No --test-states; skipping evaluation.\n";
    return 0;
  }

  // EVAL on held-out scenarios.
  std::map<std::string, LblCount> testLbl;
  long tbf = 0;
  for (auto &p : A.test_bf) load_bf_labels(p, testLbl, tbf);
  std::vector<std::pair<std::string, bool>> samples;
  long tkept = 0;
  long tunl = 0;
  process_states(A.test_states, testLbl, A.majority, A.include_bg, nullptr,
                 nullptr, &samples, tkept, tunl);
  std::cout << "\nTest: " << samples.size() << " labeled connections held out ("
            << tunl << " unlabeled skipped)\n";

  auto confusion = [&](double thr, long &tp, long &fp, long &fn, long &tn) {
    tp = fp = fn = tn = 0;
    for (const auto &s : samples) {
      bool pred = (bot.score(s.first) - norm.score(s.first)) > thr;
      if (s.second) (pred ? tp : fn)++;
      else (pred ? fp : tn)++;
    }
  };
  auto prf = [](long tp, long fp, long fn) {
    double p = (tp + fp) ? (double)tp / (tp + fp) : 0;
    double r = (tp + fn) ? (double)tp / (tp + fn) : 0;
    double f = (p + r) ? 2 * p * r / (p + r) : 0;
    return std::tuple<double, double, double>(p, r, f);
  };
  std::ofstream csv(A.out_dir + "/behavioral_eval.csv");
  csv << "threshold,TP,FP,FN,TN,precision,recall,f1\n";
  for (int sweep = 0; sweep <= 24; ++sweep) {
    const double t = -3.0 + 0.25 * sweep;
    long tp;
    long fp;
    long fn;
    long tn;
    confusion(t, tp, fp, fn, tn);
    auto [p, r, fs] = prf(tp, fp, fn);
    csv << t << "," << tp << "," << fp << "," << fn << "," << tn << "," << p
        << "," << r << "," << fs << "\n";
  }
  csv.close();
  long tp;
  long fp;
  long fn;
  long tn;
  confusion(A.threshold, tp, fp, fn, tn);
  auto [p, r, fs] = prf(tp, fp, fn);
  std::cout << "\n=== EVALUATION (train-on-pcap, threshold " << A.threshold
            << ") ===\n";
  std::cout << "Confusion: TP=" << tp << " FP=" << fp << " FN=" << fn
            << " TN=" << tn << "\n";
  printf("Precision %.3f  Recall %.3f  F1 %.3f\n", p, r, fs);
  std::cout << "Sweep -> " << A.out_dir << "/behavioral_eval.csv\n";
  std::ofstream js(A.out_dir + "/behavioral_report.json");
  js << "{\n  \"mode\": \"train-on-pcap\",\n  \"config_fingerprint\": \""
     << cfg_fp << "\",\n  \"test_labeled\": " << samples.size()
     << ",\n  \"threshold\": " << A.threshold << ",\n  \"confusion\": {\"tp\": "
     << tp << ", \"fp\": " << fp << ", \"fn\": " << fn << ", \"tn\": " << tn
     << "},\n  \"precision\": " << p << ", \"recall\": " << r << ", \"f1\": "
     << fs << "\n}\n";
  return 0;
}
