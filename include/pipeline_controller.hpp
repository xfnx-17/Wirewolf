#pragma once
#include "config.hpp"
#include "wirewolf_types.hpp"
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

class TcpReassembler;
class NpuFilter;
class LlmInference;
template <typename T> class ThreadSafeQueue;
struct FlowData;
using FlowPtr = std::unique_ptr<FlowData>;

class PipelineController {
public:
  PipelineController();
  ~PipelineController();

  PipelineController(const PipelineController &) = delete;
  PipelineController &operator=(const PipelineController &) = delete;

  // Non-blocking lifecycle
  bool start(const WirewolfConfig &config);
  void stop();

  // State
  PipelineState state() const;
  std::string last_error() const;

  // Thread-safe stats snapshot
  PipelineStats stats() const;

  // Callbacks (set before start)
  void set_on_threat_detected(OnThreatDetected cb);
  void set_on_stats_update(OnStatsUpdate cb);
  void set_on_state_change(OnStateChange cb);
  void set_on_flow_event(OnFlowEvent cb);

  // Network interface enumeration
  struct InterfaceInfo {
    std::string name;
    std::string description;
  };
  static std::vector<InterfaceInfo> list_interfaces();

private:
  void pipeline_thread_func(WirewolfConfig config);
  void set_state(PipelineState new_state);

  // Pipeline components
  std::unique_ptr<ThreadSafeQueue<FlowPtr>> queue_reassembly_to_filter_;
  std::unique_ptr<ThreadSafeQueue<FlowPtr>> queue_filter_to_llm_;
  std::unique_ptr<TcpReassembler> reassembler_;
  std::unique_ptr<NpuFilter> filter_;
  std::unique_ptr<LlmInference> llm_;

  // Threads
  std::thread pipeline_thread_;

  // State
  mutable std::mutex state_mutex_;
  PipelineState state_ = PipelineState::Stopped;
  std::string last_error_;

  // Statistics
  mutable std::mutex stats_mutex_;
  PipelineStats cached_stats_;
  std::atomic<size_t> alerts_fired_{0};

  // Callbacks
  OnThreatDetected on_threat_detected_;
  OnStatsUpdate on_stats_update_;
  OnStateChange on_state_change_;
  OnFlowEvent on_flow_event_;

  // Shutdown signal
  std::atomic<bool> shutdown_requested_{false};
  std::atomic<bool> capture_finished_{false};
};
