// wirewolf_capi.cpp — C API implementation wrapping PipelineController
#ifndef WIREWOLF_DLL_EXPORT
#define WIREWOLF_DLL_EXPORT
#endif
#include "wirewolf_capi.h"
#include "config.hpp"
#include "logger.hpp"
#include "pipeline_controller.hpp"
#include "wirewolf_types.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>

// Internal handle structure — holds the C++ objects and config
struct WirewolfInstance {
  PipelineController controller;
  WirewolfConfig config;

  // Optional push callbacks (kept for completeness; Dart uses polling)
  WirewolfAlertCallback alert_cb = nullptr;
  void *alert_cb_user_data = nullptr;
  WirewolfStateCallback state_cb = nullptr;
  void *state_cb_user_data = nullptr;

  // Thread-safe queues drained by the poll_* functions.
  static constexpr size_t MAX_QUEUE = 10000;
  std::mutex queue_mutex;
  std::deque<WirewolfAlert> pending_alerts;
  std::deque<WirewolfFlowEvent> pending_flows;
  std::deque<WirewolfLogEntry> pending_logs;
};

// Helper: safe string copy into fixed buffer
static void safe_copy(char *dst, size_t dst_size, const std::string &src) {
  size_t len = std::min(src.size(), dst_size - 1);
  std::memcpy(dst, src.data(), len);
  dst[len] = '\0';
}

// Helper: convert ThreatAlert to WirewolfAlert (flat C struct)
static WirewolfAlert convert_alert(const ThreatAlert &alert) {
  WirewolfAlert out;
  std::memset(&out, 0, sizeof(out));

  out.src_ip = alert.connection.src_ip;
  out.dst_ip = alert.connection.dst_ip;
  out.src_port = alert.connection.src_port;
  out.dst_port = alert.connection.dst_port;

  safe_copy(out.threat_type, sizeof(out.threat_type), alert.threat_type);
  safe_copy(out.severity, sizeof(out.severity), alert.severity);
  out.cvss = alert.severity_info.cvss;
  out.severity_level = static_cast<int>(alert.severity_info.level);
  safe_copy(out.snippet, sizeof(out.snippet), alert.snippet);
  safe_copy(out.raw_llm_output, sizeof(out.raw_llm_output),
            alert.raw_llm_output);
  safe_copy(out.payload_text, sizeof(out.payload_text), alert.payload_text);

  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                alert.timestamp.time_since_epoch())
                .count();
  out.timestamp_ms = static_cast<int64_t>(ms);

  // Carry the backend-computed confidence; fall back to a CVSS-derived value
  // for any older alert path that didn't set it.
  out.confidence = alert.confidence > 0.0f
                       ? alert.confidence
                       : confidence_for(alert.severity_info, false);

  return out;
}

// ── Lifecycle ──

extern "C" WIREWOLF_API WirewolfHandle wirewolf_create(void) {
  return new WirewolfInstance();
}

extern "C" WIREWOLF_API void wirewolf_destroy(WirewolfHandle handle) {
  if (!handle)
    return;
  auto *inst = static_cast<WirewolfInstance *>(handle);
  inst->controller.stop();
  delete inst;
}

// ── Configuration ──

extern "C" WIREWOLF_API void
wirewolf_set_config_interface(WirewolfHandle handle, const char *iface) {
  if (!handle || !iface)
    return;
  static_cast<WirewolfInstance *>(handle)->config.interface = iface;
}

extern "C" WIREWOLF_API void
wirewolf_set_config_llama_model(WirewolfHandle handle, const char *path) {
  if (!handle || !path)
    return;
  static_cast<WirewolfInstance *>(handle)->config.llama_model_path = path;
}

extern "C" WIREWOLF_API void
wirewolf_set_config_openvino_model(WirewolfHandle handle, const char *path) {
  if (!handle || !path)
    return;
  static_cast<WirewolfInstance *>(handle)->config.openvino_model_path = path;
}

extern "C" WIREWOLF_API void
wirewolf_set_config_openvino_enabled(WirewolfHandle handle, int enabled) {
  if (!handle)
    return;
  static_cast<WirewolfInstance *>(handle)->config.openvino_enabled =
      (enabled != 0);
}

extern "C" WIREWOLF_API void
wirewolf_set_config_log_level(WirewolfHandle handle, int level) {
  if (!handle)
    return;
  static_cast<WirewolfInstance *>(handle)->config.log_level = level;
  Logger::instance().set_level(level);
}

extern "C" WIREWOLF_API void
wirewolf_set_config_queue_capacity(WirewolfHandle handle, size_t capacity) {
  if (!handle || capacity == 0)
    return;
  static_cast<WirewolfInstance *>(handle)->config.queue_capacity = capacity;
}

extern "C" WIREWOLF_API void
wirewolf_set_config_payload_limit(WirewolfHandle handle, size_t limit) {
  if (!handle || limit == 0)
    return;
  static_cast<WirewolfInstance *>(handle)->config.payload_char_limit = limit;
}

extern "C" WIREWOLF_API void
wirewolf_set_config_max_tokens(WirewolfHandle handle, int max_tokens) {
  if (!handle || max_tokens <= 0)
    return;
  static_cast<WirewolfInstance *>(handle)->config.max_tokens = max_tokens;
}

extern "C" WIREWOLF_API void
wirewolf_set_config_gpu_layers(WirewolfHandle handle, int layers) {
  if (!handle)
    return;
  static_cast<WirewolfInstance *>(handle)->config.n_gpu_layers = layers;
}

extern "C" WIREWOLF_API void
wirewolf_set_config_context_size(WirewolfHandle handle, uint32_t size) {
  if (!handle || size == 0)
    return;
  static_cast<WirewolfInstance *>(handle)->config.context_size = size;
}

extern "C" WIREWOLF_API void
wirewolf_set_config_windivert(WirewolfHandle handle, int enabled) {
  if (!handle)
    return;
  static_cast<WirewolfInstance *>(handle)->config.use_windivert = (enabled != 0);
}

extern "C" WIREWOLF_API void
wirewolf_set_config_inline_block(WirewolfHandle handle, int enabled) {
  if (!handle)
    return;
  static_cast<WirewolfInstance *>(handle)->config.inline_block = (enabled != 0);
}

extern "C" WIREWOLF_API void
wirewolf_set_config_windivert_filter(WirewolfHandle handle,
                                     const char *filter) {
  if (!handle || !filter)
    return;
  static_cast<WirewolfInstance *>(handle)->config.windivert_filter = filter;
}

extern "C" WIREWOLF_API void
wirewolf_set_config_rules_dir(WirewolfHandle handle, const char *dir) {
  if (!handle || !dir)
    return;
  static_cast<WirewolfInstance *>(handle)->config.rules_dir = dir;
}

// Behavioral C2 Markov models directory + LLR threshold. Empty dir disables.
extern "C" WIREWOLF_API void
wirewolf_set_config_behavioral(WirewolfHandle handle, const char *dir,
                               double threshold) {
  if (!handle)
    return;
  auto *inst = static_cast<WirewolfInstance *>(handle);
  inst->config.behavioral_models_dir = dir ? dir : "";
  inst->config.behavioral_threshold = threshold;
}

// mode: 0 = Auto, 1 = Live, 2 = Forensic. Anything else is treated as Auto.
extern "C" WIREWOLF_API void
wirewolf_set_config_mode(WirewolfHandle handle, int mode) {
  if (!handle)
    return;
  AnalysisMode m = mode == 1   ? AnalysisMode::Live
                   : mode == 2 ? AnalysisMode::Forensic
                               : AnalysisMode::Auto;
  static_cast<WirewolfInstance *>(handle)->config.analysis_mode = m;
}

extern "C" WIREWOLF_API void
wirewolf_set_config_threat_db(WirewolfHandle handle, const char *path) {
  if (!handle || !path)
    return;
  static_cast<WirewolfInstance *>(handle)->config.threat_proxy_db = path;
}

extern "C" WIREWOLF_API void
wirewolf_set_config_block_allowlist(WirewolfHandle handle, const char *csv) {
  if (!handle || !csv)
    return;
  static_cast<WirewolfInstance *>(handle)->config.block_allowlist = csv;
}

// ── Callbacks ──

extern "C" WIREWOLF_API void
wirewolf_set_alert_callback(WirewolfHandle handle, WirewolfAlertCallback cb,
                            void *user_data) {
  if (!handle)
    return;
  auto *inst = static_cast<WirewolfInstance *>(handle);
  inst->alert_cb = cb;
  inst->alert_cb_user_data = user_data;
}

extern "C" WIREWOLF_API void
wirewolf_set_state_callback(WirewolfHandle handle, WirewolfStateCallback cb,
                            void *user_data) {
  if (!handle)
    return;
  auto *inst = static_cast<WirewolfInstance *>(handle);
  inst->state_cb = cb;
  inst->state_cb_user_data = user_data;
}

extern "C" WIREWOLF_API void
wirewolf_set_flow_event_callback(WirewolfHandle, WirewolfFlowEventCallback,
                                 void *) {
  // Deprecated: flow events are drained via wirewolf_poll_flow_events.
}

extern "C" WIREWOLF_API void
wirewolf_set_log_callback(WirewolfHandle, WirewolfLogCallback, void *) {
  // Deprecated: logs are drained via wirewolf_poll_logs.
}

// ── Pipeline control ──

extern "C" WIREWOLF_API int wirewolf_start(WirewolfHandle handle) {
  if (!handle)
    return 0;
  auto *inst = static_cast<WirewolfInstance *>(handle);

  // Alerts → push to queue (and optional push callback)
  inst->controller.set_on_threat_detected(
      [inst](const ThreatAlert &alert) {
        WirewolfAlert c_alert = convert_alert(alert);
        {
          std::scoped_lock lock(inst->queue_mutex);
          inst->pending_alerts.push_back(c_alert);
          if (inst->pending_alerts.size() > WirewolfInstance::MAX_QUEUE)
            inst->pending_alerts.pop_front();
        }
        if (inst->alert_cb)
          inst->alert_cb(&c_alert, inst->alert_cb_user_data);
      });

  // State change → push callback only
  if (inst->state_cb) {
    inst->controller.set_on_state_change(
        [inst](PipelineState state) {
          inst->state_cb(static_cast<int>(state), inst->state_cb_user_data);
        });
  }

  // Flow events → push to queue
  inst->controller.set_on_flow_event([inst](const FlowEvent &ev) {
    WirewolfFlowEvent c_ev;
    std::memset(&c_ev, 0, sizeof(c_ev));
    c_ev.src_ip = ev.connection.src_ip;
    c_ev.dst_ip = ev.connection.dst_ip;
    c_ev.src_port = ev.connection.src_port;
    c_ev.dst_port = ev.connection.dst_port;
    c_ev.action = static_cast<int>(ev.action);
    safe_copy(c_ev.reason, sizeof(c_ev.reason), ev.reason);
    c_ev.payload_size = ev.payload_size;
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  ev.timestamp.time_since_epoch())
                  .count();
    c_ev.timestamp_ms = static_cast<int64_t>(ms);
    std::scoped_lock lock(inst->queue_mutex);
    inst->pending_flows.push_back(c_ev);
    if (inst->pending_flows.size() > WirewolfInstance::MAX_QUEUE)
      inst->pending_flows.pop_front();
  });

  // Logs → push to queue
  Logger::instance().set_callback(
      [inst](LogLevel level, const std::string &component,
             const std::string &message) {
        WirewolfLogEntry c_log;
        std::memset(&c_log, 0, sizeof(c_log));
        c_log.level = static_cast<int>(level);
        safe_copy(c_log.component, sizeof(c_log.component), component);
        safe_copy(c_log.message, sizeof(c_log.message), message);
        std::scoped_lock lock(inst->queue_mutex);
        inst->pending_logs.push_back(c_log);
        if (inst->pending_logs.size() > WirewolfInstance::MAX_QUEUE)
          inst->pending_logs.pop_front();
      });

  return inst->controller.start(inst->config) ? 1 : 0;
}

extern "C" WIREWOLF_API void wirewolf_stop(WirewolfHandle handle) {
  if (!handle)
    return;
  static_cast<WirewolfInstance *>(handle)->controller.stop();
}

// ── State queries ──

extern "C" WIREWOLF_API int wirewolf_get_state(WirewolfHandle handle) {
  if (!handle)
    return WIREWOLF_STATE_ERROR;
  return static_cast<int>(
      static_cast<WirewolfInstance *>(handle)->controller.state());
}

extern "C" WIREWOLF_API void wirewolf_get_stats(WirewolfHandle handle,
                                                WirewolfStats *out) {
  if (!handle || !out)
    return;
  std::memset(out, 0, sizeof(WirewolfStats));

  auto stats =
      static_cast<WirewolfInstance *>(handle)->controller.stats();

  out->filter_passed = stats.filter_passed;
  out->filter_dropped = stats.filter_dropped;
  out->filter_deduped = stats.filter_deduped;
  out->alerts_fired = stats.alerts_fired;
  out->queue_reassembly_depth = stats.queue_reassembly_to_filter_depth;
  out->queue_reassembly_capacity = stats.queue_reassembly_to_filter_capacity;
  out->queue_reassembly_drops = stats.queue_reassembly_to_filter_drops;
  out->queue_llm_depth = stats.queue_filter_to_llm_depth;
  out->queue_llm_capacity = stats.queue_filter_to_llm_capacity;
  out->queue_llm_drops = stats.queue_filter_to_llm_drops;
  out->capture_finished = stats.capture_finished ? 1 : 0;
  out->blocked_packets = stats.blocked_packets;
  out->blocked_sources = stats.blocked_sources;
  safe_copy(out->filter_device, sizeof(out->filter_device),
            stats.filter_device);
}

extern "C" WIREWOLF_API int wirewolf_get_last_error(WirewolfHandle handle,
                                                    char *buf,
                                                    size_t buf_size) {
  if (!handle || !buf || buf_size == 0)
    return 0;
  std::string err =
      static_cast<WirewolfInstance *>(handle)->controller.last_error();
  if (err.empty()) {
    buf[0] = '\0';
    return 0;
  }
  safe_copy(buf, buf_size, err);
  return 1;
}

// ── Network interfaces ──

extern "C" WIREWOLF_API int wirewolf_list_interfaces(WirewolfInterface *out,
                                                     int max_count) {
  if (!out || max_count <= 0)
    return 0;

  auto interfaces = PipelineController::list_interfaces();
  int count = static_cast<int>(
      std::min(static_cast<size_t>(max_count), interfaces.size()));

  for (int i = 0; i < count; i++) {
    std::memset(&out[i], 0, sizeof(WirewolfInterface));
    safe_copy(out[i].name, sizeof(out[i].name), interfaces[i].name);
    safe_copy(out[i].description, sizeof(out[i].description),
              interfaces[i].description);
  }

  return count;
}

// ── Poll-based event draining ──

extern "C" WIREWOLF_API int wirewolf_poll_alerts(WirewolfHandle handle,
                                                  WirewolfAlert *out, int max) {
  if (!handle || !out || max <= 0)
    return 0;
  auto *inst = static_cast<WirewolfInstance *>(handle);
  std::scoped_lock lock(inst->queue_mutex);
  int n = 0;
  while (n < max && !inst->pending_alerts.empty()) {
    out[n++] = inst->pending_alerts.front();
    inst->pending_alerts.pop_front();
  }
  return n;
}

extern "C" WIREWOLF_API int wirewolf_poll_flow_events(WirewolfHandle handle,
                                                      WirewolfFlowEvent *out,
                                                      int max) {
  if (!handle || !out || max <= 0)
    return 0;
  auto *inst = static_cast<WirewolfInstance *>(handle);
  std::scoped_lock lock(inst->queue_mutex);
  int n = 0;
  while (n < max && !inst->pending_flows.empty()) {
    out[n++] = inst->pending_flows.front();
    inst->pending_flows.pop_front();
  }
  return n;
}

extern "C" WIREWOLF_API int wirewolf_poll_logs(WirewolfHandle handle,
                                               WirewolfLogEntry *out, int max) {
  if (!handle || !out || max <= 0)
    return 0;
  auto *inst = static_cast<WirewolfInstance *>(handle);
  std::scoped_lock lock(inst->queue_mutex);
  int n = 0;
  while (n < max && !inst->pending_logs.empty()) {
    out[n++] = inst->pending_logs.front();
    inst->pending_logs.pop_front();
  }
  return n;
}
