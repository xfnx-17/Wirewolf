// wirewolf_capi.h — C API for FFI (Flutter, Python, etc.)
//
// This is a thin C wrapper over PipelineController. All strings are
// null-terminated UTF-8. All functions are thread-safe.
//
// Usage:
//   WirewolfHandle h = wirewolf_create();
//   wirewolf_set_config_interface(h, "eth0");
//   wirewolf_set_config_llama_model(h, "model.gguf");
//   wirewolf_set_config_openvino_model(h, "model.xml");
//   wirewolf_set_alert_callback(h, my_callback, user_data);
//   wirewolf_start(h);
//   ...
//   wirewolf_stop(h);
//   wirewolf_destroy(h);

#ifndef WIREWOLF_CAPI_H
#define WIREWOLF_CAPI_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#ifdef WIREWOLF_DLL_EXPORT
#define WIREWOLF_API __declspec(dllexport)
#else
#define WIREWOLF_API __declspec(dllimport)
#endif
#else
#define WIREWOLF_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle
typedef void *WirewolfHandle;

// ── Pipeline state (mirrors PipelineState enum) ──
enum WirewolfState {
  WIREWOLF_STATE_STOPPED = 0,
  WIREWOLF_STATE_STARTING = 1,
  WIREWOLF_STATE_RUNNING = 2,
  WIREWOLF_STATE_STOPPING = 3,
  WIREWOLF_STATE_ERROR = 4,
};

// ── Stats snapshot (flat C struct for FFI) ──
typedef struct {
  size_t filter_passed;
  size_t filter_dropped;
  size_t filter_deduped;
  size_t alerts_fired;
  size_t queue_reassembly_depth;
  size_t queue_reassembly_capacity;
  size_t queue_reassembly_drops;
  size_t queue_llm_depth;
  size_t queue_llm_capacity;
  size_t queue_llm_drops;
  int capture_finished; // 0 or 1
  size_t blocked_packets; // IPS: packets dropped (WinDivert inline mode)
  size_t blocked_sources; // IPS: distinct source IPs blocked
  char filter_device[32];
} WirewolfStats;

// ── Alert (flat C struct for FFI) ──
// Strings are copied and null-terminated. Max lengths prevent overflow.
typedef struct {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  char threat_type[64];
  char severity[64];
  float cvss;
  int severity_level; // 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
  char snippet[512];
  char raw_llm_output[1024];
  char payload_text[4096];
  int64_t timestamp_ms; // milliseconds since epoch
  float confidence;     // detection confidence 0..1 (0 if unknown)
} WirewolfAlert;

// ── Network interface info ──
typedef struct {
  char name[256];
  char description[512];
} WirewolfInterface;

// ── Flow event (live activity feed) ──
typedef struct {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  int action;   // 0=Filtered, 1=PassedToLLM, 2=LLMCleared
  char reason[64];
  size_t payload_size;
  int64_t timestamp_ms;
} WirewolfFlowEvent;

// ── Log entry ──
typedef struct {
  int level;           // 0=DEBUG, 1=INFO, 2=WARN, 3=ERROR
  char component[32];
  char message[512];
} WirewolfLogEntry;

// ── Callback types ──
typedef void (*WirewolfAlertCallback)(const WirewolfAlert *alert,
                                     void *user_data);
typedef void (*WirewolfStateCallback)(int state, void *user_data);
typedef void (*WirewolfFlowEventCallback)(const WirewolfFlowEvent *event,
                                         void *user_data);
typedef void (*WirewolfLogCallback)(const WirewolfLogEntry *entry,
                                   void *user_data);

// ── Lifecycle ──
WIREWOLF_API WirewolfHandle wirewolf_create(void);
WIREWOLF_API void wirewolf_destroy(WirewolfHandle handle);

// ── Configuration (call before start) ──
WIREWOLF_API void wirewolf_set_config_interface(WirewolfHandle handle,
                                                const char *iface);
WIREWOLF_API void wirewolf_set_config_llama_model(WirewolfHandle handle,
                                                  const char *path);
WIREWOLF_API void wirewolf_set_config_openvino_model(WirewolfHandle handle,
                                                     const char *path);
WIREWOLF_API void wirewolf_set_config_openvino_enabled(WirewolfHandle handle,
                                                       int enabled);
WIREWOLF_API void wirewolf_set_config_log_level(WirewolfHandle handle,
                                                int level);
WIREWOLF_API void wirewolf_set_config_queue_capacity(WirewolfHandle handle,
                                                     size_t capacity);
WIREWOLF_API void wirewolf_set_config_payload_limit(WirewolfHandle handle,
                                                    size_t limit);
WIREWOLF_API void wirewolf_set_config_max_tokens(WirewolfHandle handle,
                                                 int max_tokens);
WIREWOLF_API void wirewolf_set_config_gpu_layers(WirewolfHandle handle,
                                                 int layers);
WIREWOLF_API void wirewolf_set_config_context_size(WirewolfHandle handle,
                                                   uint32_t size);
// Inline IPS mode (WinDivert). When enabled, packets are intercepted in the
// Windows TCP/IP stack instead of passively tapped. inline_block drops
// traffic from flagged sources. filter is a WinDivert filter expression.
WIREWOLF_API void wirewolf_set_config_windivert(WirewolfHandle handle,
                                                int enabled);
WIREWOLF_API void wirewolf_set_config_inline_block(WirewolfHandle handle,
                                                   int enabled);
WIREWOLF_API void wirewolf_set_config_windivert_filter(WirewolfHandle handle,
                                                       const char *filter);
// Directory of updatable threat-intel rule files (bad_ja3.txt, bad_domains.txt,
// bad_ips.txt, signatures.txt). Empty = built-in detection only.
WIREWOLF_API void wirewolf_set_config_rules_dir(WirewolfHandle handle,
                                                const char *dir);
// Operating mode: 0=Auto (Forensic for .pcap, Live for interfaces), 1=Live
// (fast detectors decide; signature hits skip the LLM), 2=Forensic (LLM also
// arbitrates signature hits).
WIREWOLF_API void wirewolf_set_config_mode(WirewolfHandle handle, int mode);
// Behavioral C2 Markov models directory + LLR threshold (empty dir disables).
WIREWOLF_API void wirewolf_set_config_behavioral(WirewolfHandle handle,
                                                 const char *dir,
                                                 double threshold);
// Path to the IP2Location PX12 proxy/threat binary (proxy.bin); enables
// threat-intel flagging of curated-malicious external IPs.
WIREWOLF_API void wirewolf_set_config_threat_db(WirewolfHandle handle,
                                                const char *path);
// Comma-separated IPs that must never be blocked by the IPS (critical assets).
WIREWOLF_API void wirewolf_set_config_block_allowlist(WirewolfHandle handle,
                                                      const char *csv);

// ── Callbacks (call before start) ──
WIREWOLF_API void wirewolf_set_alert_callback(WirewolfHandle handle,
                                              WirewolfAlertCallback cb,
                                              void *user_data);
WIREWOLF_API void wirewolf_set_state_callback(WirewolfHandle handle,
                                              WirewolfStateCallback cb,
                                              void *user_data);
WIREWOLF_API void wirewolf_set_flow_event_callback(WirewolfHandle handle,
                                                   WirewolfFlowEventCallback cb,
                                                   void *user_data);
WIREWOLF_API void wirewolf_set_log_callback(WirewolfHandle handle,
                                            WirewolfLogCallback cb,
                                            void *user_data);

// ── Pipeline control ──
WIREWOLF_API int wirewolf_start(WirewolfHandle handle);  // returns 1 on success
WIREWOLF_API void wirewolf_stop(WirewolfHandle handle);

// ── State queries ──
WIREWOLF_API int wirewolf_get_state(WirewolfHandle handle);
WIREWOLF_API void wirewolf_get_stats(WirewolfHandle handle,
                                     WirewolfStats *out);
WIREWOLF_API int wirewolf_get_last_error(WirewolfHandle handle, char *buf,
                                         size_t buf_size);

// ── Network interfaces ──
// Returns number of interfaces found. Writes up to max_count entries to out.
WIREWOLF_API int wirewolf_list_interfaces(WirewolfInterface *out,
                                          int max_count);

// ── Poll-based event draining (thread-safe) ──
// The pipeline fires alerts/events/logs from worker threads. Rather than
// invoking Dart callbacks across thread boundaries (unsafe pointer lifetime),
// the backend accumulates them in internal queues. Call these periodically
// (e.g. every 500ms) to drain new items. Each returns the number written to
// `out` (up to max), removing them from the internal queue.
WIREWOLF_API int wirewolf_poll_alerts(WirewolfHandle handle,
                                       WirewolfAlert *out, int max);
WIREWOLF_API int wirewolf_poll_flow_events(WirewolfHandle handle,
                                           WirewolfFlowEvent *out, int max);
WIREWOLF_API int wirewolf_poll_logs(WirewolfHandle handle,
                                     WirewolfLogEntry *out, int max);

#ifdef __cplusplus
}
#endif

#endif // WIREWOLF_CAPI_H
