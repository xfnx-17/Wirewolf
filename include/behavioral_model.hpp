#pragma once
// behavioral_model.hpp — clean-room behavioral C2 detection primitives.
//
// This is the SINGLE encoding + scoring implementation, shared by the offline
// trainer (tools/train_behavioral) and (in a later step) the live engine, so
// there is exactly one encoder and no drift between training and runtime.
//
// Concept (clean-room — inspired by the well-known "behavioral state string"
// idea but with our own buckets/alphabet and our own code; NOT derived from
// Stratosphere/Slips source or models):
//
//   A "connection" is the set of flows sharing a 4-tuple
//   (SrcAddr, DstAddr, Dport, Proto), ordered by start time. Each flow is
//   encoded as two characters appended to the connection's state string:
//     - a LETTER  encoding (total-bytes bucket x duration bucket)
//     - a SYMBOL  encoding the timing gap since the previous flow (periodicity)
//   e.g. "a.c-b+f-..."  (letter, symbol, letter, symbol, ...)
//
//   A first-order Markov model is trained per class (Botnet / Normal) over the
//   character alphabet with add-k (Laplace) smoothing. A connection is scored
//   by the log-likelihood-ratio between the Botnet and Normal models; the
//   decision threshold trades precision vs recall.

#include <cstdint>
#include <iosfwd>
#include <map>
#include <string>
#include <vector>

namespace behavioral {

// One flow's reusable signal (from a .binetflow row, or later from the live
// reassembler). Bytes/duration drive the letter; start_time drives the symbol.
struct Flow {
  double start_time = 0.0;  // epoch seconds (ordering + inter-arrival)
  double duration = 0.0;    // seconds
  uint64_t tot_bytes = 0;   // total bytes
};

// Encoding parameters. Defaults are the canonical values; when the live engine
// adopts this it must pass the SAME values (see check_compat / model header).
struct BehavioralConfig {
  // total-bytes bucket upper bounds (last bucket = everything larger)
  std::vector<uint64_t> byte_buckets = {128, 1024, 8192, 65536};
  // duration bucket upper bounds in seconds (last bucket = everything longer)
  std::vector<double> dur_buckets = {1.0, 10.0};
  // inter-arrival-gap bucket upper bounds in seconds → timing symbol
  // (first flow has no predecessor and uses the '.' symbol)
  std::vector<double> gap_buckets = {2.0, 60.0, 3600.0};
  double markov_k = 0.5;     // add-k (Laplace) smoothing
  size_t min_flows = 4;      // ignore connections shorter than this
  // A short fingerprint of the above so trainer and runtime can detect a
  // config mismatch that would invalidate models.
  std::string fingerprint() const;
};

// Encode one connection (flows are sorted by start_time inside) into its state
// string. Returns "" if there are fewer than 2 flows (no transitions).
std::string encode_connection(std::vector<Flow> flows, const BehavioralConfig &cfg);

// First-order Markov model over the character alphabet, with add-k smoothing.
class MarkovModel {
public:
  MarkovModel() = default;
  explicit MarkovModel(std::string label, double k = 0.5)
      : label_(std::move(label)), k_(k) {}

  const std::string &label() const { return label_; }

  // Accumulate transition counts from a connection's state string.
  void observe(const std::string &state_string);

  // Convenience: observe many.
  void train(const std::vector<std::string> &state_strings) {
    for (const auto &s : state_strings) observe(s);
  }

  // Average log-probability per transition of the string under this model
  // (uses add-k smoothing over the union alphabet). Higher = better fit.
  // Empty/one-char strings return 0.
  double score(const std::string &state_string) const;

  size_t alphabet_size() const { return alphabet_.size(); }
  long total_transitions() const { return total_; }

  // models/ serialization (text format, version 1).
  void serialize(std::ostream &os, const std::string &cfg_fingerprint) const;
  static MarkovModel load(std::istream &is, std::string *cfg_fingerprint = nullptr);

private:
  std::string label_;
  double k_ = 0.5;
  std::map<char, std::map<char, long>> counts_; // from -> (to -> count)
  std::map<char, long> row_totals_;             // from -> total out-count
  std::map<char, bool> alphabet_;               // observed chars (from or to)
  long total_ = 0;
  double log_prob(char from, char to) const;
};

} // namespace behavioral
