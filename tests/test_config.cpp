#include <catch2/catch_test_macros.hpp>
#include "config.hpp"

TEST_CASE("Config defaults are sane", "[config]") {
  WirewolfConfig cfg;

  REQUIRE(cfg.queue_capacity == 1024);
  REQUIRE(cfg.max_flow_payload_bytes == 1048576);
  REQUIRE(cfg.payload_char_limit == 2048);
  REQUIRE(cfg.max_tokens == 512);
  REQUIRE(cfg.max_prompt_tokens == 7000);
  REQUIRE(cfg.n_gpu_layers == 99);
  REQUIRE(cfg.context_size == 8192);
  REQUIRE(cfg.log_level == 1);
  REQUIRE(cfg.entropy_high_threshold == 7.0f);
  REQUIRE(cfg.entropy_low_threshold == 1.0f);
  REQUIRE_FALSE(cfg.openvino_enabled);
  REQUIRE_FALSE(cfg.valid());
}

TEST_CASE("Config parse with minimum args", "[config]") {
  const char *argv[] = {"wirewolf", "eth0", "model.xml", "llama.gguf"};
  auto cfg = WirewolfConfig::parse(4, const_cast<char **>(argv));

  REQUIRE(cfg.valid());
  REQUIRE(cfg.interface == "eth0");
  REQUIRE(cfg.openvino_model_path == "model.xml");
  REQUIRE(cfg.llama_model_path == "llama.gguf");
}

TEST_CASE("Config parse with optional flags", "[config]") {
  const char *argv[] = {"wirewolf",     "eth0",   "model.xml",
                        "llama.gguf",   "--log-level", "0",
                        "--queue-capacity", "512", "--payload-limit",
                        "4096",         "--max-tokens", "256",
                        "--openvino"};
  auto cfg = WirewolfConfig::parse(13, const_cast<char **>(argv));

  REQUIRE(cfg.valid());
  REQUIRE(cfg.log_level == 0);
  REQUIRE(cfg.queue_capacity == 512);
  REQUIRE(cfg.payload_char_limit == 4096);
  REQUIRE(cfg.max_tokens == 256);
  REQUIRE(cfg.openvino_enabled);
}

TEST_CASE("Config parse with too few args is invalid", "[config]") {
  const char *argv[] = {"wirewolf", "eth0"};
  auto cfg = WirewolfConfig::parse(2, const_cast<char **>(argv));

  REQUIRE_FALSE(cfg.valid());
}

TEST_CASE("Config parse with pcap file", "[config]") {
  const char *argv[] = {"wirewolf", "capture.pcap", "model.xml", "llama.gguf"};
  auto cfg = WirewolfConfig::parse(4, const_cast<char **>(argv));

  REQUIRE(cfg.valid());
  REQUIRE(cfg.interface == "capture.pcap");
}

TEST_CASE("Config entropy thresholds", "[config]") {
  const char *argv[] = {"wirewolf",      "eth0",     "model.xml",
                        "llama.gguf",    "--entropy-high", "6.5",
                        "--entropy-low",  "0.5"};
  auto cfg = WirewolfConfig::parse(8, const_cast<char **>(argv));

  REQUIRE(cfg.entropy_high_threshold == 6.5f);
  REQUIRE(cfg.entropy_low_threshold == 0.5f);
}
