#include "behavioral_model.hpp"

#include <algorithm>
#include <cmath>
#include <istream>
#include <ostream>
#include <sstream>

namespace behavioral {

// Bucket index for a value against ascending upper bounds; last bucket is the
// open-ended "everything larger".
template <typename T, typename V>
static size_t bucket_of(V v, const std::vector<T> &bounds) {
  for (size_t i = 0; i < bounds.size(); ++i)
    if (v < static_cast<V>(bounds[i])) return i;
  return bounds.size();
}

std::string BehavioralConfig::fingerprint() const {
  std::ostringstream os;
  os << "bytes:";
  for (auto b : byte_buckets) os << b << ",";
  os << "|dur:";
  for (auto d : dur_buckets) os << d << ",";
  os << "|gap:";
  for (auto g : gap_buckets) os << g << ",";
  os << "|k:" << markov_k << "|min:" << min_flows;
  return os.str();
}

std::string encode_connection(std::vector<Flow> flows, const BehavioralConfig &cfg) {
  if (flows.size() < 2) return "";
  std::sort(flows.begin(), flows.end(),
            [](const Flow &a, const Flow &b) { return a.start_time < b.start_time; });

  const size_t n_size = cfg.byte_buckets.size() + 1; // letters span size x dur
  // Timing symbols: index 0 = first flow ('.'); then one per gap bucket.
  static const char *kSymbols = ".-+*#%@"; // up to gap_buckets+1 symbols

  std::string out;
  out.reserve(flows.size() * 2);
  double prev_start = 0.0;
  bool have_prev = false;

  for (const auto &f : flows) {
    size_t sb = bucket_of(f.tot_bytes, cfg.byte_buckets);
    size_t db = bucket_of(f.duration, cfg.dur_buckets);
    // LETTER from (size, duration): 'a' + size*nDur + dur
    char letter = static_cast<char>('a' + (sb * (cfg.dur_buckets.size() + 1) + db));
    out.push_back(letter);

    // SYMBOL from inter-arrival gap (periodicity); first flow → '.'
    size_t sym_idx;
    if (!have_prev) {
      sym_idx = 0;
    } else {
      double gap = f.start_time - prev_start;
      if (gap < 0) gap = 0;
      sym_idx = 1 + bucket_of(gap, cfg.gap_buckets);
    }
    size_t max_sym = sizeof(".-+*#%@") - 1; // count of symbol chars
    if (sym_idx >= max_sym) sym_idx = max_sym - 1;
    out.push_back(kSymbols[sym_idx]);

    prev_start = f.start_time;
    have_prev = true;
    (void)n_size;
  }
  return out;
}

void MarkovModel::observe(const std::string &s) {
  if (s.size() < 2) return;
  alphabet_[s[0]] = true;
  for (size_t i = 1; i < s.size(); ++i) {
    char from = s[i - 1];
    char to = s[i];
    counts_[from][to] += 1;
    row_totals_[from] += 1;
    alphabet_[to] = true;
    ++total_;
  }
}

double MarkovModel::log_prob(char from, char to) const {
  const double V = static_cast<double>(alphabet_.size());
  long c = 0;
  auto it = counts_.find(from);
  if (it != counts_.end()) {
    auto jt = it->second.find(to);
    if (jt != it->second.end()) c = jt->second;
  }
  long rt = 0;
  auto rit = row_totals_.find(from);
  if (rit != row_totals_.end()) rt = rit->second;
  // add-k (Laplace): (c + k) / (rowTotal + k*V)
  double p = (c + k_) / (static_cast<double>(rt) + k_ * V);
  return std::log(p);
}

double MarkovModel::score(const std::string &s) const {
  if (s.size() < 2 || alphabet_.empty()) return 0.0;
  double sum = 0.0;
  long n = 0;
  for (size_t i = 1; i < s.size(); ++i) {
    sum += log_prob(s[i - 1], s[i]);
    ++n;
  }
  return n ? sum / n : 0.0;
}

void MarkovModel::serialize(std::ostream &os, const std::string &cfg_fp) const {
  os << "WIREWOLF-BEHAVIORAL-MODEL v1\n";
  os << "label " << label_ << "\n";
  os << "k " << k_ << "\n";
  os << "config " << cfg_fp << "\n";
  std::string alpha;
  for (auto &kv : alphabet_) alpha.push_back(kv.first);
  os << "alphabet " << alpha << "\n";
  os << "transitions " << counts_.size() << "\n";
  for (auto &row : counts_) {
    os << row.first << " " << row.second.size();
    for (auto &to : row.second) os << " " << to.first << ":" << to.second;
    os << "\n";
  }
}

MarkovModel MarkovModel::load(std::istream &is, std::string *cfg_fp) {
  MarkovModel m;
  std::string line;
  std::getline(is, line); // header/version (ignored beyond presence)
  while (std::getline(is, line)) {
    if (line.empty()) continue;
    std::istringstream ss(line);
    std::string key;
    ss >> key;
    if (key == "label") {
      ss >> m.label_;
    } else if (key == "k") {
      ss >> m.k_;
    } else if (key == "config") {
      std::string fp;
      std::getline(ss, fp);
      if (!fp.empty() && fp[0] == ' ') fp.erase(0, 1);
      if (cfg_fp) *cfg_fp = fp;
    } else if (key == "alphabet") {
      std::string alpha;
      ss >> alpha;
      for (char c : alpha) m.alphabet_[c] = true;
    } else if (key == "transitions") {
      size_t rows = 0;
      ss >> rows;
      for (size_t r = 0; r < rows; ++r) {
        if (!std::getline(is, line)) break;
        std::istringstream rs(line);
        char from;
        size_t cnt = 0;
        rs >> from >> cnt;
        std::string tok;
        while (rs >> tok) {
          auto pos = tok.find(':');
          if (pos == std::string::npos) continue;
          char to = tok[0];
          long c = std::stol(tok.substr(pos + 1));
          m.counts_[from][to] = c;
          m.row_totals_[from] += c;
          m.total_ += c;
          m.alphabet_[from] = true;
          m.alphabet_[to] = true;
        }
      }
    }
  }
  return m;
}

} // namespace behavioral
