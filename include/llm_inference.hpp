#pragma once
#include "config.hpp"
#include "packet_types.hpp"
#include "wirewolf_types.hpp"
#include "thread_safe_queue.hpp"
#include <atomic>
#include <functional>
#include <llama.h>
#include <memory>
#include <string>
#include <thread>

class LlmInference {
public:
  using AlertCallback = std::function<void(const std::string &llm_output,
                                          const FlowData *flow,
                                          const std::string &payload_text)>;

  LlmInference(const WirewolfConfig &config,
               ThreadSafeQueue<FlowPtr> &in_queue);
  ~LlmInference();
  void start();
  void stop();

  void set_alert_callback(AlertCallback cb) {
    alert_callback_ = std::move(cb);
  }

  void set_flow_event_callback(OnFlowEvent cb) {
    flow_event_callback_ = std::move(cb);
  }

private:
  void worker_loop();
  std::string generate_response(const std::string &prompt);

  ThreadSafeQueue<FlowPtr> &input_queue;
  std::atomic<bool> running{false};
  std::thread worker;
  const WirewolfConfig &cfg;

  llama_model *model;
  llama_context *ctx;

  AlertCallback alert_callback_;
  OnFlowEvent flow_event_callback_;
  size_t llm_runs_ = 0; // flows actually inferred (for max_llm_flows budget)
};
