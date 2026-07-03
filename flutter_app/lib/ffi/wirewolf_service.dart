import 'dart:async';
import 'dart:ffi';
import 'package:ffi/ffi.dart';
import 'wirewolf_bindings.dart';

// ── Dart-friendly data classes ──

class AlertData {
  final String srcIp;
  final int srcPort;
  final String dstIp;
  final int dstPort;
  final String threatType;
  final String severity;
  final double cvss;
  final int severityLevel;
  final String snippet;
  final String rawLlmOutput;
  final String payloadText;
  final DateTime timestamp;
  final double confidence; // 0..1 from backend; 0 if unknown

  AlertData({
    required this.srcIp, required this.srcPort,
    required this.dstIp, required this.dstPort,
    required this.threatType, required this.severity,
    required this.cvss, required this.severityLevel,
    required this.snippet, required this.rawLlmOutput,
    required this.payloadText, required this.timestamp,
    this.confidence = 0,
  });

  /// Confidence as a 0..100 percentage. Falls back to a severity-derived
  /// estimate when the backend didn't provide one (e.g. demo data).
  int get confidencePct {
    if (confidence > 0) return (confidence * 100).round().clamp(1, 100);
    return switch (severityLevel) {
      4 => 95, 3 => 86, 2 => 72, 1 => 58, _ => 45,
    };
  }

  String get severityLabel => switch (severityLevel) {
    4 => 'Critical', 3 => 'High', 2 => 'Medium', 1 => 'Low', _ => 'Info',
  };

  String get cvssFormatted => '$severityLabel (CVSS 4.0: ${cvss.toStringAsFixed(1)})';
}

class StatsData {
  final int filterPassed;
  final int filterDropped;
  final int filterDeduped;
  final int alertsFired;
  final int queueReassemblyDepth;
  final int queueReassemblyCapacity;
  final int queueReassemblyDrops;
  final int queueLlmDepth;
  final int queueLlmCapacity;
  final int queueLlmDrops;
  final bool captureFinished;
  final int blockedPackets;
  final int blockedSources;
  final String filterDevice;

  StatsData({
    required this.filterPassed, required this.filterDropped,
    required this.filterDeduped, required this.alertsFired,
    required this.queueReassemblyDepth, required this.queueReassemblyCapacity,
    required this.queueReassemblyDrops, required this.queueLlmDepth,
    required this.queueLlmCapacity, required this.queueLlmDrops,
    required this.captureFinished, required this.blockedPackets,
    required this.blockedSources, required this.filterDevice,
  });

  int get totalFlows => filterPassed + filterDropped;
  double get passRate => totalFlows > 0 ? filterPassed / totalFlows * 100 : 0;
}

class FlowEventData {
  final String srcIp;
  final int srcPort;
  final String dstIp;
  final int dstPort;
  final int action; // 0=Filtered, 1=PassedToLLM, 2=LLMCleared
  final String reason;
  final int payloadSize;
  final DateTime timestamp;

  FlowEventData({
    required this.srcIp, required this.srcPort,
    required this.dstIp, required this.dstPort,
    required this.action, required this.reason,
    required this.payloadSize, required this.timestamp,
  });
}

class LogEntryData {
  final int level; // 0=DEBUG, 1=INFO, 2=WARN, 3=ERROR
  final String component;
  final String message;
  final DateTime timestamp;

  LogEntryData({
    required this.level, required this.component,
    required this.message, required this.timestamp,
  });
}

enum PipelineState { stopped, starting, running, stopping, error }

// ── Singleton service that manages the native backend ──

class WirewolfService {
  late final WirewolfBindings _bindings;
  Pointer<Void>? _handle;
  Timer? _statsTimer;

  final _alertController = StreamController<AlertData>.broadcast();
  final _statsController = StreamController<StatsData>.broadcast();
  final _stateController = StreamController<PipelineState>.broadcast();
  final _flowController = StreamController<FlowEventData>.broadcast();
  final _logController = StreamController<LogEntryData>.broadcast();

  Stream<AlertData> get alerts => _alertController.stream;
  Stream<StatsData> get stats => _statsController.stream;
  Stream<PipelineState> get stateChanges => _stateController.stream;
  Stream<FlowEventData> get flowEvents => _flowController.stream;
  Stream<LogEntryData> get logs => _logController.stream;

  final List<AlertData> alertHistory = [];
  StatsData? latestStats;
  PipelineState currentState = PipelineState.stopped;

  bool _initialized = false;
  String? _dllPath;

  WirewolfService(String dllPath) {
    _dllPath = dllPath;
  }

  bool get isInitialized => _initialized;

  /// Try to load the DLL and create the native handle.
  /// Returns null on success, or an error message on failure.
  String? initialize() {
    try {
      _bindings = WirewolfBindings(_dllPath!);
      _handle = _bindings.create();
      _initialized = true;
      return null;
    } catch (e) {
      return 'Failed to load wirewolf.dll: $e';
    }
  }

  // ── Configuration ──
  void setInterface(String iface) => _bindings.setInterface(_handle!, iface);
  void setLlamaModel(String path) => _bindings.setLlamaModel(_handle!, path);
  void setOpenvinoModel(String path) => _bindings.setOpenvinoModel(_handle!, path);
  void setOpenvinoEnabled(bool enabled) => _bindings.setOpenvinoEnabled(_handle!, enabled);
  void setLogLevel(int level) => _bindings.setLogLevel(_handle!, level);
  void setGpuLayers(int layers) => _bindings.setGpuLayers(_handle!, layers);
  void setContextSize(int size) => _bindings.setContextSize(_handle!, size);
  void setWindivert(bool enabled) => _bindings.setWindivert(_handle!, enabled);
  void setInlineBlock(bool enabled) => _bindings.setInlineBlock(_handle!, enabled);
  void setWindivertFilter(String filter) => _bindings.setWindivertFilter(_handle!, filter);
  void setRulesDir(String dir) => _bindings.setRulesDir(_handle!, dir);
  void setThreatDb(String path) => _bindings.setThreatDb(_handle!, path);
  void setBlockAllowlist(String csv) => _bindings.setBlockAllowlist(_handle!, csv);
  // mode: 0 = Auto, 1 = Live, 2 = Forensic
  void setMode(int mode) => _bindings.setMode(_handle!, mode);
  // Behavioral C2 models dir + LLR threshold (empty dir = disabled).
  void setBehavioral(String dir, double threshold) =>
      _bindings.setBehavioral(_handle!, dir, threshold);

  // ── Pipeline control ──
  bool start() {
    if (_handle == null) return false;

    final success = _bindings.start(_handle!);
    if (success) {
      currentState = PipelineState.starting;
      _stateController.add(currentState);

      _statsTimer = Timer.periodic(const Duration(milliseconds: 500), (_) {
        _pollStats();
        _pollState();
        _pollAlerts();
        _pollFlows();
        _pollLogs();
      });
    }
    return success;
  }

  void stop() {
    if (_handle == null) return;
    // Request shutdown. The C++ pipeline tears down asynchronously
    // (Stopping -> Stopped over a few seconds). Keep the poll timer
    // running so _pollState observes the transition; it cancels itself
    // once the pipeline reports Stopped.
    _bindings.stop(_handle!);
  }

  // ── Queries ──
  List<({String name, String description})> listInterfaces() =>
      _initialized ? _bindings.listInterfaces() : [];

  String? getLastError() =>
      _handle != null ? _bindings.getLastError(_handle!) : null;

  // ── Polling ──
  void _pollStats() {
    if (_handle == null) return;
    final ptr = calloc<WirewolfStats>();
    _bindings.getStats(_handle!, ptr);
    final s = ptr.ref;
    final data = StatsData(
      filterPassed: s.filterPassed,
      filterDropped: s.filterDropped,
      filterDeduped: s.filterDeduped,
      alertsFired: s.alertsFired,
      queueReassemblyDepth: s.queueReassemblyDepth,
      queueReassemblyCapacity: s.queueReassemblyCapacity,
      queueReassemblyDrops: s.queueReassemblyDrops,
      queueLlmDepth: s.queueLlmDepth,
      queueLlmCapacity: s.queueLlmCapacity,
      queueLlmDrops: s.queueLlmDrops,
      captureFinished: s.captureFinished != 0,
      blockedPackets: s.blockedPackets,
      blockedSources: s.blockedSources,
      filterDevice: s.filterDeviceStr,
    );
    calloc.free(ptr);
    latestStats = data;
    _statsController.add(data);
  }

  void _pollState() {
    if (_handle == null) return;
    final raw = _bindings.getState(_handle!);
    final state = PipelineState.values[raw.clamp(0, 4)];
    if (state != currentState) {
      currentState = state;
      _stateController.add(state);
    }
    // Once fully stopped (or errored), drain any final events and halt polling.
    if (state == PipelineState.stopped || state == PipelineState.error) {
      _pollAlerts();
      _pollFlows();
      _pollLogs();
      _pollStats();
      _statsTimer?.cancel();
      _statsTimer = null;
    }
  }

  void _pollAlerts() {
    if (_handle == null) return;
    _bindings.pollAlerts(_handle!, 64, (a) {
      final data = AlertData(
        srcIp: a.srcIpStr, srcPort: a.srcPortHost,
        dstIp: a.dstIpStr, dstPort: a.dstPortHost,
        threatType: a.threatTypeStr, severity: a.severityStr,
        cvss: a.cvss, severityLevel: a.severityLevel,
        snippet: a.snippetStr, rawLlmOutput: a.rawLlmOutputStr,
        payloadText: a.payloadTextStr,
        timestamp: DateTime.fromMillisecondsSinceEpoch(a.timestampMs),
        confidence: a.confidence,
      );
      alertHistory.add(data);
      _alertController.add(data);
    });
  }

  void _pollFlows() {
    if (_handle == null) return;
    _bindings.pollFlowEvents(_handle!, 256, (e) {
      _flowController.add(FlowEventData(
        srcIp: e.srcIpStr, srcPort: e.srcPortHost,
        dstIp: e.dstIpStr, dstPort: e.dstPortHost,
        action: e.action, reason: e.reasonStr,
        payloadSize: e.payloadSize,
        timestamp: DateTime.fromMillisecondsSinceEpoch(e.timestampMs),
      ));
    });
  }

  void _pollLogs() {
    if (_handle == null) return;
    _bindings.pollLogs(_handle!, 256, (l) {
      _logController.add(LogEntryData(
        level: l.level, component: l.componentStr,
        message: l.messageStr, timestamp: DateTime.now(),
      ));
    });
  }

  // ── Cleanup ──
  void dispose() {
    _statsTimer?.cancel();
    if (_handle != null) {
      _bindings.stop(_handle!);
      _bindings.destroy(_handle!);
      _handle = null;
    }
    _alertController.close();
    _statsController.close();
    _stateController.close();
    _flowController.close();
    _logController.close();
  }
}
