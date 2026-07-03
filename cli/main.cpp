#include "config.hpp"
#include "logger.hpp"
#include "pipeline_controller.hpp"
#include "wirewolf_types.hpp"
#include <csignal>
#include <iostream>
#include <thread>

static PipelineController *g_controller = nullptr;

void signal_handler(int) {
  if (g_controller)
    g_controller->stop();
}

int main(int argc, char *argv[]) {
  WirewolfConfig cfg = WirewolfConfig::parse(argc, argv);

  if (!cfg.valid()) {
    if (!cfg.parse_error.empty())
      LOG_ERROR("main", cfg.parse_error);
    LOG_ERROR("main", "Usage: wirewolf <interface|file.pcap> "
                      "<openvino_model.xml> <llama_model.gguf> [options]\n"
                      "  --log-level N       0=DEBUG 1=INFO 2=WARN 3=ERROR\n"
                      "  --queue-capacity N  Max items per queue (default 1024)\n"
                      "  --payload-limit N   Max chars sent to LLM (default 2048)\n"
                      "  --max-tokens N      Max LLM output tokens (default 512)\n"
                      "  --max-flow-size N   Flow size trigger in bytes (default 1MB)\n"
                      "  --openvino          Enable OpenVINO model (default: statistical filter)\n"
                      "  --entropy-high F    High entropy threshold (default 7.0)\n"
                      "  --entropy-low F     Low entropy threshold (default 1.0)\n"
                      "  --no-promisc        Disable promiscuous mode on capture interface\n"
                      "  --mode M            live|forensic|auto (default auto: forensic for .pcap, live for interfaces)\n"
                      "  --max-llm-flows N   Cap flows sent to the LLM (0=unlimited); bounds run time on big captures");
    return 1;
  }

  Logger::instance().set_level(cfg.log_level);
  LOG_INFO("main", "Wirewolf starting...");

  std::signal(SIGINT, signal_handler);
  std::signal(SIGTERM, signal_handler);

  PipelineController controller;
  g_controller = &controller;

  controller.set_on_threat_detected([](const ThreatAlert &alert) {
    // IPs stored in network byte order (big-endian from IP header)
    auto ip_str = [](uint32_t ip) {
      return std::to_string(ip & 0xFF) + "." +
             std::to_string((ip >> 8) & 0xFF) + "." +
             std::to_string((ip >> 16) & 0xFF) + "." +
             std::to_string((ip >> 24) & 0xFF);
    };
    std::string src = ip_str(alert.connection.src_ip);
    std::string dst = ip_str(alert.connection.dst_ip);

    std::cout << "\n*** ALERT ***\n"
              << "  Type:     " << alert.threat_type << "\n"
              << "  Severity: " << alert.severity_info.format() << "\n"
              << "  Source:   " << src << ":"
              << static_cast<uint16_t>((alert.connection.src_port >> 8) | (alert.connection.src_port << 8)) << "\n"
              << "  Dest:     " << dst << ":"
              << static_cast<uint16_t>((alert.connection.dst_port >> 8) | (alert.connection.dst_port << 8)) << "\n";
    if (!alert.snippet.empty())
      std::cout << "  Snippet:  " << alert.snippet.substr(0, 200) << "\n";
    std::cout << std::flush;
  });

  controller.set_on_state_change([](PipelineState state) {
    if (state == PipelineState::Error) {
      LOG_ERROR("main", "Pipeline entered error state");
    }
  });

  if (!controller.start(cfg)) {
    LOG_ERROR("main", "Failed to start pipeline");
    g_controller = nullptr; // controller dies with this frame; unhook handler
    return 1;
  }

  // Block until pipeline stops
  while (controller.state() == PipelineState::Starting ||
         controller.state() == PipelineState::Running) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }

  g_controller = nullptr;

  if (controller.state() == PipelineState::Error) {
    LOG_ERROR("main", "Pipeline error: " + controller.last_error());
    return 1;
  }

  return 0;
}
