// wirewolf_bindings.dart — Dart FFI bindings for wirewolf.dll
// Auto-generated from wirewolf_capi.h — do not edit manually.

import 'dart:ffi';
import 'package:ffi/ffi.dart';

// ── C Struct: WirewolfStats ──
final class WirewolfStats extends Struct {
  @Size()
  external int filterPassed;
  @Size()
  external int filterDropped;
  @Size()
  external int filterDeduped;
  @Size()
  external int alertsFired;
  @Size()
  external int queueReassemblyDepth;
  @Size()
  external int queueReassemblyCapacity;
  @Size()
  external int queueReassemblyDrops;
  @Size()
  external int queueLlmDepth;
  @Size()
  external int queueLlmCapacity;
  @Size()
  external int queueLlmDrops;
  @Int32()
  external int captureFinished;
  @Size()
  external int blockedPackets;
  @Size()
  external int blockedSources;
  @Array(32)
  external Array<Uint8> filterDevice;

  String get filterDeviceStr {
    final list = <int>[];
    for (int i = 0; i < 32; i++) {
      final c = filterDevice[i];
      if (c == 0) break;
      list.add(c);
    }
    return String.fromCharCodes(list);
  }
}

// ── C Struct: WirewolfAlert ──
final class WirewolfAlert extends Struct {
  @Uint32()
  external int srcIp;
  @Uint32()
  external int dstIp;
  @Uint16()
  external int srcPort;
  @Uint16()
  external int dstPort;
  @Array(64)
  external Array<Uint8> threatType;
  @Array(64)
  external Array<Uint8> severity;
  @Float()
  external double cvss;
  @Int32()
  external int severityLevel;
  @Array(512)
  external Array<Uint8> snippet;
  @Array(1024)
  external Array<Uint8> rawLlmOutput;
  @Array(4096)
  external Array<Uint8> payloadText;
  @Int64()
  external int timestampMs;
  @Float()
  external double confidence;

  String _readArray(Array<Uint8> arr, int maxLen) {
    final list = <int>[];
    for (int i = 0; i < maxLen; i++) {
      final c = arr[i];
      if (c == 0) break;
      list.add(c);
    }
    return String.fromCharCodes(list);
  }

  String get threatTypeStr => _readArray(threatType, 64);
  String get severityStr => _readArray(severity, 64);
  String get snippetStr => _readArray(snippet, 512);
  String get rawLlmOutputStr => _readArray(rawLlmOutput, 1024);
  String get payloadTextStr => _readArray(payloadText, 4096);

  String get srcIpStr => _ipToString(srcIp);
  String get dstIpStr => _ipToString(dstIp);
  int get srcPortHost => ((srcPort >> 8) & 0xFF) | ((srcPort & 0xFF) << 8);
  int get dstPortHost => ((dstPort >> 8) & 0xFF) | ((dstPort & 0xFF) << 8);

  String _ipToString(int ip) =>
      '${ip & 0xFF}.${(ip >> 8) & 0xFF}.${(ip >> 16) & 0xFF}.${(ip >> 24) & 0xFF}';
}

// ── C Struct: WirewolfFlowEvent ──
final class WirewolfFlowEvent extends Struct {
  @Uint32()
  external int srcIp;
  @Uint32()
  external int dstIp;
  @Uint16()
  external int srcPort;
  @Uint16()
  external int dstPort;
  @Int32()
  external int action;
  @Array(64)
  external Array<Uint8> reason;
  @Size()
  external int payloadSize;
  @Int64()
  external int timestampMs;

  String get reasonStr {
    final list = <int>[];
    for (int i = 0; i < 64; i++) {
      final c = reason[i];
      if (c == 0) break;
      list.add(c);
    }
    return String.fromCharCodes(list);
  }

  String _ip(int ip) =>
      '${ip & 0xFF}.${(ip >> 8) & 0xFF}.${(ip >> 16) & 0xFF}.${(ip >> 24) & 0xFF}';
  String get srcIpStr => _ip(srcIp);
  String get dstIpStr => _ip(dstIp);
  int get srcPortHost => ((srcPort >> 8) & 0xFF) | ((srcPort & 0xFF) << 8);
  int get dstPortHost => ((dstPort >> 8) & 0xFF) | ((dstPort & 0xFF) << 8);
}

// ── C Struct: WirewolfLogEntry ──
final class WirewolfLogEntry extends Struct {
  @Int32()
  external int level;
  @Array(32)
  external Array<Uint8> component;
  @Array(512)
  external Array<Uint8> message;

  String _read(Array<Uint8> arr, int maxLen) {
    final list = <int>[];
    for (int i = 0; i < maxLen; i++) {
      final c = arr[i];
      if (c == 0) break;
      list.add(c);
    }
    return String.fromCharCodes(list);
  }

  String get componentStr => _read(component, 32);
  String get messageStr => _read(message, 512);
}

// ── C Struct: WirewolfInterface ──
final class WirewolfInterface extends Struct {
  @Array(256)
  external Array<Uint8> name;
  @Array(512)
  external Array<Uint8> description;

  String _readArray(Array<Uint8> arr, int maxLen) {
    final list = <int>[];
    for (int i = 0; i < maxLen; i++) {
      final c = arr[i];
      if (c == 0) break;
      list.add(c);
    }
    return String.fromCharCodes(list);
  }

  String get nameStr => _readArray(name, 256);
  String get descriptionStr => _readArray(description, 512);
}

// ── Callback types ──
typedef WirewolfAlertCallbackNative = Void Function(
    Pointer<WirewolfAlert>, Pointer<Void>);
typedef WirewolfStateCallbackNative = Void Function(Int32, Pointer<Void>);

// ── Native function typedefs ──
typedef _CreateNative = Pointer<Void> Function();
typedef _CreateDart = Pointer<Void> Function();

typedef _DestroyNative = Void Function(Pointer<Void>);
typedef _DestroyDart = void Function(Pointer<Void>);

typedef _SetStringNative = Void Function(Pointer<Void>, Pointer<Utf8>);
typedef _SetStringDart = void Function(Pointer<Void>, Pointer<Utf8>);

typedef _SetIntNative = Void Function(Pointer<Void>, Int32);
typedef _SetIntDart = void Function(Pointer<Void>, int);
typedef _SetBehavioralNative = Void Function(
    Pointer<Void>, Pointer<Utf8>, Double);
typedef _SetBehavioralDart = void Function(Pointer<Void>, Pointer<Utf8>, double);

typedef _SetSizeNative = Void Function(Pointer<Void>, Size);
typedef _SetSizeDart = void Function(Pointer<Void>, int);

typedef _SetUint32Native = Void Function(Pointer<Void>, Uint32);
typedef _SetUint32Dart = void Function(Pointer<Void>, int);

typedef _SetAlertCbNative = Void Function(
    Pointer<Void>,
    Pointer<NativeFunction<WirewolfAlertCallbackNative>>,
    Pointer<Void>);
typedef _SetAlertCbDart = void Function(
    Pointer<Void>,
    Pointer<NativeFunction<WirewolfAlertCallbackNative>>,
    Pointer<Void>);

typedef _SetStateCbNative = Void Function(
    Pointer<Void>,
    Pointer<NativeFunction<WirewolfStateCallbackNative>>,
    Pointer<Void>);
typedef _SetStateCbDart = void Function(
    Pointer<Void>,
    Pointer<NativeFunction<WirewolfStateCallbackNative>>,
    Pointer<Void>);

typedef _StartNative = Int32 Function(Pointer<Void>);
typedef _StartDart = int Function(Pointer<Void>);

typedef _StopNative = Void Function(Pointer<Void>);
typedef _StopDart = void Function(Pointer<Void>);

typedef _GetStateNative = Int32 Function(Pointer<Void>);
typedef _GetStateDart = int Function(Pointer<Void>);

typedef _GetStatsNative = Void Function(Pointer<Void>, Pointer<WirewolfStats>);
typedef _GetStatsDart = void Function(Pointer<Void>, Pointer<WirewolfStats>);

typedef _GetErrorNative = Int32 Function(Pointer<Void>, Pointer<Utf8>, Size);
typedef _GetErrorDart = int Function(Pointer<Void>, Pointer<Utf8>, int);

typedef _ListInterfacesNative = Int32 Function(
    Pointer<WirewolfInterface>, Int32);
typedef _ListInterfacesDart = int Function(Pointer<WirewolfInterface>, int);

typedef _PollAlertsNative = Int32 Function(
    Pointer<Void>, Pointer<WirewolfAlert>, Int32);
typedef _PollAlertsDart = int Function(
    Pointer<Void>, Pointer<WirewolfAlert>, int);

typedef _PollFlowsNative = Int32 Function(
    Pointer<Void>, Pointer<WirewolfFlowEvent>, Int32);
typedef _PollFlowsDart = int Function(
    Pointer<Void>, Pointer<WirewolfFlowEvent>, int);

typedef _PollLogsNative = Int32 Function(
    Pointer<Void>, Pointer<WirewolfLogEntry>, Int32);
typedef _PollLogsDart = int Function(
    Pointer<Void>, Pointer<WirewolfLogEntry>, int);

// ── Binding class ──
class WirewolfBindings {
  late final DynamicLibrary _lib;

  late final _CreateDart _create;
  late final _DestroyDart _destroy;
  late final _SetStringDart _setInterface;
  late final _SetStringDart _setLlamaModel;
  late final _SetStringDart _setOpenvinoModel;
  late final _SetIntDart _setOpenvinoEnabled;
  late final _SetIntDart _setLogLevel;
  late final _SetSizeDart _setQueueCapacity;
  late final _SetSizeDart _setPayloadLimit;
  late final _SetIntDart _setMaxTokens;
  late final _SetIntDart _setGpuLayers;
  late final _SetUint32Dart _setContextSize;
  late final _SetIntDart _setWindivert;
  late final _SetIntDart _setInlineBlock;
  late final _SetStringDart _setWindivertFilter;
  late final _SetStringDart _setRulesDir;
  late final _SetStringDart _setThreatDb;
  late final _SetIntDart _setMode;
  late final _SetBehavioralDart _setBehavioral;
  late final _SetStringDart _setBlockAllowlist;
  late final _SetAlertCbDart _setAlertCallback;
  late final _SetStateCbDart _setStateCallback;
  late final _StartDart _start;
  late final _StopDart _stop;
  late final _GetStateDart _getState;
  late final _GetStatsDart _getStats;
  late final _GetErrorDart _getError;
  late final _ListInterfacesDart _listInterfaces;
  late final _PollAlertsDart _pollAlerts;
  late final _PollFlowsDart _pollFlows;
  late final _PollLogsDart _pollLogs;

  WirewolfBindings(String dllPath) {
    _lib = DynamicLibrary.open(dllPath);

    _create = _lib.lookupFunction<_CreateNative, _CreateDart>(
        'wirewolf_create');
    _destroy = _lib.lookupFunction<_DestroyNative, _DestroyDart>(
        'wirewolf_destroy');
    _setInterface = _lib.lookupFunction<_SetStringNative, _SetStringDart>(
        'wirewolf_set_config_interface');
    _setLlamaModel = _lib.lookupFunction<_SetStringNative, _SetStringDart>(
        'wirewolf_set_config_llama_model');
    _setOpenvinoModel = _lib.lookupFunction<_SetStringNative, _SetStringDart>(
        'wirewolf_set_config_openvino_model');
    _setOpenvinoEnabled = _lib.lookupFunction<_SetIntNative, _SetIntDart>(
        'wirewolf_set_config_openvino_enabled');
    _setLogLevel = _lib.lookupFunction<_SetIntNative, _SetIntDart>(
        'wirewolf_set_config_log_level');
    _setQueueCapacity = _lib.lookupFunction<_SetSizeNative, _SetSizeDart>(
        'wirewolf_set_config_queue_capacity');
    _setPayloadLimit = _lib.lookupFunction<_SetSizeNative, _SetSizeDart>(
        'wirewolf_set_config_payload_limit');
    _setMaxTokens = _lib.lookupFunction<_SetIntNative, _SetIntDart>(
        'wirewolf_set_config_max_tokens');
    _setGpuLayers = _lib.lookupFunction<_SetIntNative, _SetIntDart>(
        'wirewolf_set_config_gpu_layers');
    _setContextSize = _lib.lookupFunction<_SetUint32Native, _SetUint32Dart>(
        'wirewolf_set_config_context_size');
    _setWindivert = _lib.lookupFunction<_SetIntNative, _SetIntDart>(
        'wirewolf_set_config_windivert');
    _setInlineBlock = _lib.lookupFunction<_SetIntNative, _SetIntDart>(
        'wirewolf_set_config_inline_block');
    _setWindivertFilter = _lib.lookupFunction<_SetStringNative, _SetStringDart>(
        'wirewolf_set_config_windivert_filter');
    _setRulesDir = _lib.lookupFunction<_SetStringNative, _SetStringDart>(
        'wirewolf_set_config_rules_dir');
    _setThreatDb = _lib.lookupFunction<_SetStringNative, _SetStringDart>(
        'wirewolf_set_config_threat_db');
    _setMode = _lib.lookupFunction<_SetIntNative, _SetIntDart>(
        'wirewolf_set_config_mode');
    _setBehavioral = _lib.lookupFunction<_SetBehavioralNative, _SetBehavioralDart>(
        'wirewolf_set_config_behavioral');
    _setBlockAllowlist = _lib.lookupFunction<_SetStringNative, _SetStringDart>(
        'wirewolf_set_config_block_allowlist');
    _setAlertCallback = _lib.lookupFunction<_SetAlertCbNative, _SetAlertCbDart>(
        'wirewolf_set_alert_callback');
    _setStateCallback =
        _lib.lookupFunction<_SetStateCbNative, _SetStateCbDart>(
            'wirewolf_set_state_callback');
    _start =
        _lib.lookupFunction<_StartNative, _StartDart>('wirewolf_start');
    _stop = _lib.lookupFunction<_StopNative, _StopDart>('wirewolf_stop');
    _getState = _lib.lookupFunction<_GetStateNative, _GetStateDart>(
        'wirewolf_get_state');
    _getStats = _lib.lookupFunction<_GetStatsNative, _GetStatsDart>(
        'wirewolf_get_stats');
    _getError = _lib.lookupFunction<_GetErrorNative, _GetErrorDart>(
        'wirewolf_get_last_error');
    _listInterfaces =
        _lib.lookupFunction<_ListInterfacesNative, _ListInterfacesDart>(
            'wirewolf_list_interfaces');
    _pollAlerts = _lib.lookupFunction<_PollAlertsNative, _PollAlertsDart>(
        'wirewolf_poll_alerts');
    _pollFlows = _lib.lookupFunction<_PollFlowsNative, _PollFlowsDart>(
        'wirewolf_poll_flow_events');
    _pollLogs = _lib.lookupFunction<_PollLogsNative, _PollLogsDart>(
        'wirewolf_poll_logs');
  }

  Pointer<Void> create() => _create();
  void destroy(Pointer<Void> h) => _destroy(h);

  void setInterface(Pointer<Void> h, String iface) {
    final p = iface.toNativeUtf8();
    _setInterface(h, p);
    calloc.free(p);
  }

  void setLlamaModel(Pointer<Void> h, String path) {
    final p = path.toNativeUtf8();
    _setLlamaModel(h, p);
    calloc.free(p);
  }

  void setOpenvinoModel(Pointer<Void> h, String path) {
    final p = path.toNativeUtf8();
    _setOpenvinoModel(h, p);
    calloc.free(p);
  }

  void setOpenvinoEnabled(Pointer<Void> h, bool enabled) =>
      _setOpenvinoEnabled(h, enabled ? 1 : 0);
  void setLogLevel(Pointer<Void> h, int level) => _setLogLevel(h, level);
  void setQueueCapacity(Pointer<Void> h, int cap) =>
      _setQueueCapacity(h, cap);
  void setPayloadLimit(Pointer<Void> h, int limit) =>
      _setPayloadLimit(h, limit);
  void setMaxTokens(Pointer<Void> h, int tokens) => _setMaxTokens(h, tokens);
  void setGpuLayers(Pointer<Void> h, int layers) => _setGpuLayers(h, layers);
  void setContextSize(Pointer<Void> h, int size) => _setContextSize(h, size);
  void setWindivert(Pointer<Void> h, bool enabled) => _setWindivert(h, enabled ? 1 : 0);
  void setInlineBlock(Pointer<Void> h, bool enabled) => _setInlineBlock(h, enabled ? 1 : 0);
  void setWindivertFilter(Pointer<Void> h, String filter) {
    final p = filter.toNativeUtf8();
    _setWindivertFilter(h, p);
    calloc.free(p);
  }

  void setRulesDir(Pointer<Void> h, String dir) {
    final p = dir.toNativeUtf8();
    _setRulesDir(h, p);
    calloc.free(p);
  }

  void setThreatDb(Pointer<Void> h, String path) {
    final p = path.toNativeUtf8();
    _setThreatDb(h, p);
    calloc.free(p);
  }

  // mode: 0 = Auto, 1 = Live, 2 = Forensic
  void setMode(Pointer<Void> h, int mode) => _setMode(h, mode);

  void setBehavioral(Pointer<Void> h, String dir, double threshold) {
    final p = dir.toNativeUtf8();
    _setBehavioral(h, p, threshold);
    calloc.free(p);
  }

  void setBlockAllowlist(Pointer<Void> h, String csv) {
    final p = csv.toNativeUtf8();
    _setBlockAllowlist(h, p);
    calloc.free(p);
  }

  void setAlertCallback(
      Pointer<Void> h,
      Pointer<NativeFunction<WirewolfAlertCallbackNative>> cb,
      Pointer<Void> userData) =>
      _setAlertCallback(h, cb, userData);

  void setStateCallback(
      Pointer<Void> h,
      Pointer<NativeFunction<WirewolfStateCallbackNative>> cb,
      Pointer<Void> userData) =>
      _setStateCallback(h, cb, userData);

  bool start(Pointer<Void> h) => _start(h) == 1;
  void stop(Pointer<Void> h) => _stop(h);
  int getState(Pointer<Void> h) => _getState(h);

  void getStats(Pointer<Void> h, Pointer<WirewolfStats> out) =>
      _getStats(h, out);

  String? getLastError(Pointer<Void> h) {
    final buf = calloc<Uint8>(1024).cast<Utf8>();
    final has = _getError(h, buf, 1024);
    final result = has == 1 ? buf.toDartString() : null;
    calloc.free(buf);
    return result;
  }

  List<({String name, String description})> listInterfaces() {
    final buf = calloc<WirewolfInterface>(64);
    final count = _listInterfaces(buf, 64);
    final result = <({String name, String description})>[];
    for (int i = 0; i < count; i++) {
      result.add((
        name: buf[i].nameStr,
        description: buf[i].descriptionStr,
      ));
    }
    calloc.free(buf);
    return result;
  }

  /// Drain up to [max] pending alerts. Calls [onAlert] for each.
  void pollAlerts(Pointer<Void> h, int max,
      void Function(WirewolfAlert) onAlert) {
    final buf = calloc<WirewolfAlert>(max);
    final count = _pollAlerts(h, buf, max);
    for (int i = 0; i < count; i++) {
      onAlert(buf[i]);
    }
    calloc.free(buf);
  }

  void pollFlowEvents(Pointer<Void> h, int max,
      void Function(WirewolfFlowEvent) onEvent) {
    final buf = calloc<WirewolfFlowEvent>(max);
    final count = _pollFlows(h, buf, max);
    for (int i = 0; i < count; i++) {
      onEvent(buf[i]);
    }
    calloc.free(buf);
  }

  void pollLogs(Pointer<Void> h, int max,
      void Function(WirewolfLogEntry) onLog) {
    final buf = calloc<WirewolfLogEntry>(max);
    final count = _pollLogs(h, buf, max);
    for (int i = 0; i < count; i++) {
      onLog(buf[i]);
    }
    calloc.free(buf);
  }
}
