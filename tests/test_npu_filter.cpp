#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_floating_point.hpp>
#include "config.hpp"
#include "packet_types.hpp"
#include "thread_safe_queue.hpp"
#include <array>
#include <cmath>
#include <vector>

// Replicate the feature extraction logic for unit testing
// without needing the full NpuFilter class (which requires OpenVINO linkage)
namespace {

struct FeatureExtractor {
  static std::vector<float> extract(const FlowData &flow) {
    if (flow.reassembled_payload.empty()) {
      return {0.0f, static_cast<float>(flow.length_variance),
              static_cast<float>(flow.inter_arrival_time)};
    }

    std::array<size_t, 256> counts = {0};
    for (uint8_t byte : flow.reassembled_payload)
      counts[byte]++;

    double entropy = 0.0;
    size_t total = flow.reassembled_payload.size();
    for (size_t c : counts) {
      if (c > 0) {
        double p = static_cast<double>(c) / total;
        entropy -= p * std::log2(p);
      }
    }

    return {static_cast<float>(entropy),
            static_cast<float>(flow.length_variance),
            static_cast<float>(flow.inter_arrival_time)};
  }

  static bool should_pass(const std::vector<float> &features,
                          const FlowData &flow,
                          const WirewolfConfig &cfg) {
    float entropy = features[0];
    float variance = features[1];
    float inter_arrival = features[2];

    if (entropy > cfg.entropy_high_threshold)
      return true;
    if (entropy < cfg.entropy_low_threshold &&
        flow.reassembled_payload.size() > cfg.min_payload_for_low_entropy)
      return true;
    if (variance > cfg.variance_threshold)
      return true;
    if (inter_arrival < cfg.inter_arrival_floor && inter_arrival > 0.0f &&
        flow.packet_count > cfg.min_packet_count_for_flood)
      return true;

    if (!flow.reassembled_payload.empty() &&
        flow.reassembled_payload.size() < 4096) {
      size_t suspicious_chars = 0;
      for (uint8_t b : flow.reassembled_payload) {
        if (b == '\'' || b == '"' || b == '<' || b == '>' || b == '{' ||
            b == '}' || b == '|' || b == ';' || b == '`')
          suspicious_chars++;
      }
      double ratio = static_cast<double>(suspicious_chars) /
                     flow.reassembled_payload.size();
      if (ratio > 0.05)
        return true;
    }

    return false;
  }
};

} // namespace

TEST_CASE("Feature extraction: empty payload", "[filter]") {
  FlowData flow;
  flow.length_variance = 100.0;
  flow.inter_arrival_time = 0.5;

  auto features = FeatureExtractor::extract(flow);
  REQUIRE(features.size() == 3);
  REQUIRE(features[0] == 0.0f); // entropy
  REQUIRE_THAT(features[1], Catch::Matchers::WithinAbs(100.0f, 0.01f));
  REQUIRE_THAT(features[2], Catch::Matchers::WithinAbs(0.5f, 0.01f));
}

TEST_CASE("Feature extraction: uniform bytes = max entropy", "[filter]") {
  FlowData flow;
  // Fill with all 256 byte values equally
  for (int i = 0; i < 256; i++) {
    for (int j = 0; j < 4; j++) {
      flow.reassembled_payload.push_back(static_cast<uint8_t>(i));
    }
  }
  flow.length_variance = 0.0;
  flow.inter_arrival_time = 1.0;

  auto features = FeatureExtractor::extract(flow);
  // Max entropy for 256 symbols = 8.0
  REQUIRE_THAT(features[0], Catch::Matchers::WithinAbs(8.0f, 0.01f));
}

TEST_CASE("Feature extraction: single byte value = zero entropy", "[filter]") {
  FlowData flow;
  flow.reassembled_payload.assign(100, 'A');
  flow.length_variance = 0.0;
  flow.inter_arrival_time = 1.0;

  auto features = FeatureExtractor::extract(flow);
  REQUIRE_THAT(features[0], Catch::Matchers::WithinAbs(0.0f, 0.01f));
}

TEST_CASE("Statistical filter: high entropy triggers pass", "[filter]") {
  WirewolfConfig cfg;
  FlowData flow;
  // Create high-entropy payload (random-like)
  for (int i = 0; i < 256; i++) {
    for (int j = 0; j < 4; j++) {
      flow.reassembled_payload.push_back(static_cast<uint8_t>(i));
    }
  }
  flow.length_variance = 0.0;
  flow.inter_arrival_time = 1.0;
  flow.packet_count = 10;

  auto features = FeatureExtractor::extract(flow);
  REQUIRE(features[0] > cfg.entropy_high_threshold);
  REQUIRE(FeatureExtractor::should_pass(features, flow, cfg));
}

TEST_CASE("Statistical filter: benign HTTP traffic passes through", "[filter]") {
  WirewolfConfig cfg;
  FlowData flow;
  // Normal HTTP response-like content
  std::string http = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                     "Hello World this is a normal web page with regular content "
                     "and no suspicious characters at all just plain text.";
  flow.reassembled_payload.assign(http.begin(), http.end());
  flow.length_variance = 50.0;
  flow.inter_arrival_time = 0.1;
  flow.packet_count = 5;

  auto features = FeatureExtractor::extract(flow);
  REQUIRE_FALSE(FeatureExtractor::should_pass(features, flow, cfg));
}

TEST_CASE("Statistical filter: SQL injection triggers pass", "[filter]") {
  WirewolfConfig cfg;
  FlowData flow;
  std::string sqli = "GET /users?id=1' OR '1'='1' UNION SELECT * FROM "
                     "passwords WHERE '1'='1'; DROP TABLE users;-- HTTP/1.1";
  flow.reassembled_payload.assign(sqli.begin(), sqli.end());
  flow.length_variance = 10.0;
  flow.inter_arrival_time = 0.5;
  flow.packet_count = 3;

  auto features = FeatureExtractor::extract(flow);
  // Should detect high ratio of suspicious chars (', ;, etc.)
  REQUIRE(FeatureExtractor::should_pass(features, flow, cfg));
}

TEST_CASE("Statistical filter: XSS payload triggers pass", "[filter]") {
  WirewolfConfig cfg;
  FlowData flow;
  std::string xss = "<script>alert('xss')</script><img src=x "
                     "onerror=\"alert('xss')\">";
  flow.reassembled_payload.assign(xss.begin(), xss.end());
  flow.length_variance = 5.0;
  flow.inter_arrival_time = 0.5;
  flow.packet_count = 2;

  auto features = FeatureExtractor::extract(flow);
  REQUIRE(FeatureExtractor::should_pass(features, flow, cfg));
}

TEST_CASE("Statistical filter: flood pattern triggers pass", "[filter]") {
  WirewolfConfig cfg;
  FlowData flow;
  flow.reassembled_payload.assign(100, 'A');
  flow.length_variance = 0.0;
  flow.inter_arrival_time = 0.0001; // Very fast
  flow.packet_count = 100;          // Many packets

  auto features = FeatureExtractor::extract(flow);
  REQUIRE(FeatureExtractor::should_pass(features, flow, cfg));
}

TEST_CASE("Statistical filter: low entropy large payload triggers pass",
          "[filter]") {
  WirewolfConfig cfg;
  FlowData flow;
  // Large payload with very low entropy (lots of padding)
  flow.reassembled_payload.assign(1000, 0x00);
  flow.length_variance = 0.0;
  flow.inter_arrival_time = 1.0;
  flow.packet_count = 5;

  auto features = FeatureExtractor::extract(flow);
  REQUIRE(features[0] < cfg.entropy_low_threshold);
  REQUIRE(flow.reassembled_payload.size() > cfg.min_payload_for_low_entropy);
  REQUIRE(FeatureExtractor::should_pass(features, flow, cfg));
}

TEST_CASE("Statistical filter: high variance triggers pass", "[filter]") {
  WirewolfConfig cfg;
  FlowData flow;
  flow.reassembled_payload.assign(100, 'A');
  flow.length_variance = 60000.0; // Above threshold
  flow.inter_arrival_time = 1.0;
  flow.packet_count = 10;

  auto features = FeatureExtractor::extract(flow);
  REQUIRE(FeatureExtractor::should_pass(features, flow, cfg));
}
