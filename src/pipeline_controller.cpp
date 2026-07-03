#include "pipeline_controller.hpp"
#include "llm_inference.hpp"
#include "logger.hpp"
#include "npu_filter.hpp"
#include "tcp_reassembly.hpp"
#include "thread_safe_queue.hpp"

#include <chrono>
#include <sstream>

// pcap headers for list_interfaces
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#ifndef WPCAP
#define WPCAP
#endif
#ifndef HAVE_REMOTE
#define HAVE_REMOTE
#endif
#include <pcap.h>
#else
#include <pcap.h>
#endif

PipelineController::PipelineController() = default;

PipelineController::~PipelineController() {
  stop();
  if (pipeline_thread_.joinable())
    pipeline_thread_.join();
}

bool PipelineController::start(const WirewolfConfig &config) {
  {
    std::lock_guard<std::mutex> lock(state_mutex_);
    if (state_ != PipelineState::Stopped && state_ != PipelineState::Error)
      return false;
  }

  if (!config.valid())
    return false;

  shutdown_requested_ = false;
  alerts_fired_ = 0;
  set_state(PipelineState::Starting);

  // Wait for any previous pipeline thread to finish
  if (pipeline_thread_.joinable())
    pipeline_thread_.join();

  pipeline_thread_ =
      std::thread(&PipelineController::pipeline_thread_func, this, config);
  return true;
}

void PipelineController::stop() {
  shutdown_requested_ = true;
  if (reassembler_)
    reassembler_->stop();
}

PipelineState PipelineController::state() const {
  std::lock_guard<std::mutex> lock(state_mutex_);
  return state_;
}

std::string PipelineController::last_error() const {
  std::lock_guard<std::mutex> lock(state_mutex_);
  return last_error_;
}

PipelineStats PipelineController::stats() const {
  std::lock_guard<std::mutex> lock(stats_mutex_);
  return cached_stats_;
}

void PipelineController::set_on_threat_detected(OnThreatDetected cb) {
  on_threat_detected_ = std::move(cb);
}

void PipelineController::set_on_stats_update(OnStatsUpdate cb) {
  on_stats_update_ = std::move(cb);
}

void PipelineController::set_on_state_change(OnStateChange cb) {
  on_state_change_ = std::move(cb);
}

void PipelineController::set_on_flow_event(OnFlowEvent cb) {
  on_flow_event_ = std::move(cb);
}

void PipelineController::set_state(PipelineState new_state) {
  {
    std::lock_guard<std::mutex> lock(state_mutex_);
    state_ = new_state;
  }
  if (on_state_change_)
    on_state_change_(new_state);
}

std::vector<PipelineController::InterfaceInfo>
PipelineController::list_interfaces() {
  std::vector<InterfaceInfo> result;
  pcap_if_t *alldevs;
  char errbuf[PCAP_ERRBUF_SIZE];

  if (pcap_findalldevs(&alldevs, errbuf) == -1)
    return result;

  for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
    InterfaceInfo info;
    info.name = d->name;
    info.description = d->description ? d->description : "";
    result.push_back(std::move(info));
  }

  pcap_freealldevs(alldevs);
  return result;
}

void PipelineController::pipeline_thread_func(WirewolfConfig config) {
  try {
    bool is_offline = config.is_offline_capture();

    queue_reassembly_to_filter_ =
        std::make_unique<ThreadSafeQueue<FlowPtr>>(config.queue_capacity);
    queue_filter_to_llm_ =
        std::make_unique<ThreadSafeQueue<FlowPtr>>(config.queue_capacity);

    // Offline PCAP mode: enable backpressure so no flows are dropped.
    // push() blocks when queue is full instead of dropping, creating
    // natural flow control: reassembler waits for filter, filter waits
    // for LLM. Every flow gets analyzed.
    if (is_offline) {
      queue_reassembly_to_filter_->set_blocking(true);
      queue_filter_to_llm_->set_blocking(true);
      LOG_INFO("pipeline",
               "Offline PCAP mode — backpressure enabled (zero-drop)");
    }

    reassembler_ = std::make_unique<TcpReassembler>(
        config, *queue_reassembly_to_filter_);
    // IPS safety: load the never-block allowlist for critical assets.
    if (!config.block_allowlist.empty())
      reassembler_->set_block_allowlist(config.block_allowlist);
    filter_ = std::make_unique<NpuFilter>(
        config, *queue_reassembly_to_filter_, *queue_filter_to_llm_);
    llm_ = std::make_unique<LlmInference>(config, *queue_filter_to_llm_);

    // Wire connection-level anomaly alerts (port scan, brute force, DDoS)
    if (on_threat_detected_) {
      reassembler_->set_on_threat_detected(
          [this](const ThreatAlert &alert) {
            alerts_fired_.fetch_add(1, std::memory_order_relaxed);
            on_threat_detected_(alert);
          });
    }

    // Wire flow event callbacks
    if (on_flow_event_) {
      filter_->set_flow_event_callback(on_flow_event_);
      llm_->set_flow_event_callback(on_flow_event_);
    }

    // Wire alert callback
    const bool inline_block = config.inline_block;
    llm_->set_alert_callback(
        [this, inline_block](const std::string &llm_output, const FlowData *flow,
               const std::string &payload_text) {
          alerts_fired_.fetch_add(1, std::memory_order_relaxed);

          if (on_threat_detected_) {
            ThreatAlert alert;
            alert.timestamp = std::chrono::system_clock::now();
            alert.connection = flow->id;
            alert.raw_llm_output = llm_output;
            alert.payload_text = payload_text;

            auto extract = [&](const std::string &key) -> std::string {
              auto pos = llm_output.find("\"" + key + "\"");
              if (pos == std::string::npos)
                return "";
              pos = llm_output.find(':', pos + key.size() + 2);
              if (pos == std::string::npos)
                return "";
              auto start = llm_output.find('"', pos + 1);
              if (start == std::string::npos)
                return "";
              std::string result;
              for (size_t i = start + 1; i < llm_output.size(); ++i) {
                if (llm_output[i] == '\\' && i + 1 < llm_output.size()) {
                  char next = llm_output[i + 1];
                  switch (next) {
                  case '"':  result += '"';  break;
                  case '\\': result += '\\'; break;
                  case 'n':  result += '\n'; break;
                  case 'r':  result += '\r'; break;
                  case 't':  result += '\t'; break;
                  default:   result += next; break;
                  }
                  ++i;
                } else if (llm_output[i] == '"') {
                  return result;
                } else {
                  result += llm_output[i];
                }
              }
              return "";
            };

            alert.threat_type = extract("threat_type");
            alert.severity_info = severity_for_threat(alert.threat_type);
            alert.severity = alert.severity_info.label();
            alert.snippet = extract("snippet");
            // LLM-classified detection (already passed snippet validation +
            // FP suppression upstream) — non-deterministic confidence.
            alert.confidence = confidence_for(alert.severity_info, false);

            // IPS: in inline mode, block the source of an LLM-confirmed threat
            // so its subsequent packets are dropped from the stack.
            if (inline_block && reassembler_)
              reassembler_->block_source(alert.connection.src_ip);

            on_threat_detected_(alert);
          }
        });

    llm_->start();
    filter_->start();

    capture_finished_ = false;
    std::thread pcap_thread([this]() {
      reassembler_->start();
      capture_finished_ = true;
    });

    set_state(PipelineState::Running);
    LOG_INFO("pipeline", "All pipeline stages running.");

    // Monitor loop
    while (!shutdown_requested_) {
      std::this_thread::sleep_for(std::chrono::milliseconds(500));

      // Update stats
      PipelineStats s;
      s.filter_passed = filter_->get_passed_count();
      s.filter_dropped = filter_->get_filtered_count();
      s.filter_deduped = filter_->get_dedup_count();
      s.filter_device = filter_->get_device();
      s.alerts_fired = alerts_fired_.load(std::memory_order_relaxed);
      s.queue_reassembly_to_filter_depth =
          queue_reassembly_to_filter_->size();
      s.queue_filter_to_llm_depth = queue_filter_to_llm_->size();
      s.queue_reassembly_to_filter_drops =
          queue_reassembly_to_filter_->get_dropped_count();
      s.queue_filter_to_llm_drops =
          queue_filter_to_llm_->get_dropped_count();
      s.queue_reassembly_to_filter_capacity =
          queue_reassembly_to_filter_->capacity();
      s.queue_filter_to_llm_capacity = queue_filter_to_llm_->capacity();
      s.capture_finished = capture_finished_.load(std::memory_order_relaxed);
      if (reassembler_) {
        s.blocked_packets = reassembler_->blocked_packet_count();
        s.blocked_sources = reassembler_->blocked_source_count();
      }

      {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        cached_stats_ = s;
      }

      if (on_stats_update_)
        on_stats_update_(s);

      // Log queue drops
      if (s.queue_reassembly_to_filter_drops > 0 ||
          s.queue_filter_to_llm_drops > 0) {
        LOG_WARN("pipeline",
                 "Queue drops — reassembly->filter: " +
                     std::to_string(s.queue_reassembly_to_filter_drops) +
                     " filter->llm: " +
                     std::to_string(s.queue_filter_to_llm_drops));
      }

      // For offline PCAP analysis: auto-stop once capture ends and
      // all queued flows have been processed through the pipeline.
      if (is_offline && capture_finished_) {
        if (s.queue_reassembly_to_filter_depth == 0 &&
            s.queue_filter_to_llm_depth == 0) {
          // Give LLM a moment to finish any in-flight inference
          std::this_thread::sleep_for(std::chrono::seconds(2));
          LOG_INFO("pipeline",
                   "Offline capture complete — all flows processed.");
          break;
        }
      }
    }

    // Orderly shutdown
    set_state(PipelineState::Stopping);
    LOG_INFO("pipeline", "Shutting down...");

    reassembler_->stop();

    // Disable backpressure so any blocked pushers unblock immediately.
    // This prevents deadlock when the user hits Ctrl+C while the
    // reassembler is waiting for queue space.
    queue_reassembly_to_filter_->set_blocking(false);
    queue_filter_to_llm_->set_blocking(false);

    if (pcap_thread.joinable())
      pcap_thread.join();

    queue_reassembly_to_filter_->finish();
    filter_->stop();

    LOG_INFO("pipeline",
             "Filter stats — passed: " +
                 std::to_string(filter_->get_passed_count()) +
                 " filtered: " +
                 std::to_string(filter_->get_filtered_count()) +
                 " deduped: " +
                 std::to_string(filter_->get_dedup_count()));

    queue_filter_to_llm_->finish();
    llm_->stop();

    LOG_INFO("pipeline", "Shutdown complete.");

    // Clean up components
    llm_.reset();
    filter_.reset();
    reassembler_.reset();
    queue_filter_to_llm_.reset();
    queue_reassembly_to_filter_.reset();

    set_state(PipelineState::Stopped);

  } catch (const std::exception &e) {
    std::string err = e.what();
    LOG_ERROR("pipeline", "Fatal error: " + err);

    // Clean up whatever was created
    llm_.reset();
    filter_.reset();
    reassembler_.reset();
    queue_filter_to_llm_.reset();
    queue_reassembly_to_filter_.reset();

    {
      std::lock_guard<std::mutex> lock(state_mutex_);
      last_error_ = err;
    }
    set_state(PipelineState::Error);
  }
}
