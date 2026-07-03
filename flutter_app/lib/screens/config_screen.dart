import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import '../ffi/wirewolf_service.dart';
import '../theme/app_theme.dart';

class ConfigScreen extends StatefulWidget {
  final WirewolfService? service;
  final VoidCallback onStart;
  final VoidCallback onStop;
  final PipelineState pipelineState;

  const ConfigScreen({
    super.key,
    this.service,
    required this.onStart,
    required this.onStop,
    required this.pipelineState,
  });

  @override
  State<ConfigScreen> createState() => _ConfigScreenState();
}

class _ConfigScreenState extends State<ConfigScreen> {
  final _interfaceController = TextEditingController();
  final _pcapController = TextEditingController();
  final _llamaController = TextEditingController();
  final _openvinoController = TextEditingController();

  int _selectedInterface = -1;
  List<({String name, String description})> _interfaces = [];
  bool _openvinoEnabled = false;
  int _mode = 0; // 0=Auto, 1=Live, 2=Forensic
  int _logLevel = 1;
  int _gpuLayers = 99;
  int _contextSize = 8192;
  double _entropyHigh = 7.0;
  double _entropyLow = 1.0;
  double _npuThreshold = 0.5;
  bool _useWindivert = false;
  bool _inlineBlock = false;
  final _filterController = TextEditingController(text: 'tcp');
  final _rulesController = TextEditingController();
  final _allowlistController = TextEditingController();

  @override
  void initState() {
    super.initState();
    _loadInterfaces();
  }

  void _loadInterfaces() {
    if (widget.service != null) {
      _interfaces = widget.service!.listInterfaces();
    }
    setState(() {});
  }

  bool get _isRunning =>
      widget.pipelineState == PipelineState.running ||
      widget.pipelineState == PipelineState.starting ||
      widget.pipelineState == PipelineState.stopping;

  void _applyAndStart() {
    final svc = widget.service;
    if (svc != null && svc.isInitialized) {
      // PCAP file path overrides interface selection if provided
      if (_pcapController.text.trim().isNotEmpty) {
        svc.setInterface(_pcapController.text.trim());
      } else if (_selectedInterface >= 0) {
        svc.setInterface(_interfaces[_selectedInterface].name);
      }
      svc.setLlamaModel(_llamaController.text.trim());
      svc.setOpenvinoModel(_openvinoController.text.trim());
      svc.setOpenvinoEnabled(_openvinoEnabled);
      svc.setLogLevel(_logLevel);
      svc.setGpuLayers(_gpuLayers);
      svc.setContextSize(_contextSize);
      svc.setWindivert(_useWindivert);
      svc.setInlineBlock(_useWindivert && _inlineBlock);
      svc.setWindivertFilter(_filterController.text.trim().isEmpty
          ? 'tcp'
          : _filterController.text.trim());
      svc.setRulesDir(_rulesController.text.trim());
      svc.setBlockAllowlist(_allowlistController.text.trim());
      svc.setMode(_mode);
      // Behavioral C2 models are auto-loaded at startup (see main._setupBehavioral).
    }
    widget.onStart();
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Pipeline control
          _buildPipelineControl(),
          const SizedBox(height: 20),

          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Left column: Capture + Models
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _buildSection('Network Capture', [
                      _buildInterfaceDropdown(),
                      const SizedBox(height: 8),
                      _buildFileField('Or PCAP file', _pcapController, ['pcap', 'pcapng'],
                          info: 'Analyze a previously captured .pcap/.pcapng file offline '
                              'instead of live traffic. Every flow is processed with zero '
                              'packet drops. Takes priority over the interface above.'),
                    ], info: 'Where Wirewolf reads network traffic from — either a live '
                        'network adapter or a saved capture file.'),
                    const SizedBox(height: 16),
                    _buildSection('Models', [
                      _buildFileField('LLaMA Model (.gguf)', _llamaController, ['gguf'],
                          info: 'The local LLM (GGUF format) that inspects suspicious '
                              'payloads and classifies threats. Runs on your GPU via '
                              'llama.cpp. An 8B model quantized to Q4 (~5 GB) fits your card.'),
                      const SizedBox(height: 8),
                      _buildFileField('OpenVINO Model (.xml)', _openvinoController, ['xml'],
                          info: 'Optional CNN model for the pre-filter stage, run on an '
                              'Intel NPU/GPU via OpenVINO. Only needed if "Use OpenVINO" is '
                              'on. Without it, a fast statistical filter is used instead.'),
                      const SizedBox(height: 8),
                      _buildToggle('Use OpenVINO', _openvinoEnabled, (v) => setState(() => _openvinoEnabled = v),
                          info: 'Use the OpenVINO neural pre-filter instead of the built-in '
                              'statistical filter. Requires an OpenVINO model and Intel '
                              'hardware. Leave off to use the statistical filter (recommended '
                              'on NVIDIA-only systems).'),
                    ], info: 'The AI models powering the two analysis stages: a fast '
                        'pre-filter and the deep-inspection LLM.'),
                  ],
                ),
              ),
              const SizedBox(width: 20),
              // Right column: Thresholds + Advanced
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _buildSection('Filter Thresholds', [
                      _buildSlider('Entropy High', _entropyHigh, 0, 8, (v) => setState(() => _entropyHigh = v),
                          info: 'Flows whose payload entropy exceeds this are flagged as '
                              'suspicious (encrypted/compressed/obfuscated data). 8.0 is the '
                              'max for random bytes. Default 7.0. Lower = more flows escalated.'),
                      _buildSlider('Entropy Low', _entropyLow, 0, 4, (v) => setState(() => _entropyLow = v),
                          info: 'Large payloads with entropy below this are flagged — unusually '
                              'uniform data can indicate padding or covert channels. Default 1.0.'),
                      if (_openvinoEnabled)
                        _buildSlider('NPU Threshold', _npuThreshold, 0.1, 0.95, (v) => setState(() => _npuThreshold = v),
                            info: 'Confidence cutoff for the OpenVINO CNN pre-filter. Higher = '
                                'fewer flows sent to the LLM (less GPU load); lower = more '
                                'thorough analysis. Default 0.5.'),
                    ], info: 'Tuning for the fast statistical pre-filter that decides which '
                        'flows are worth sending to the LLM.'),
                    const SizedBox(height: 16),
                    _buildSection('Capture Mode', [
                      _buildDropdown('Operating Mode',
                          ['Auto', 'Live (NIDS)', 'Forensic'], _mode,
                          (v) => setState(() => _mode = v),
                          info: 'Auto = Forensic for a .pcap, Live for an interface. '
                              'Live = real-time NIDS; fast detectors decide and a '
                              'signature hit skips the LLM to stay real-time. '
                              'Forensic = deep offline analysis; the LLM also '
                              'arbitrates signature hits and nothing is dropped.'),
                      const SizedBox(height: 8),
                      _buildToggle('Inline IPS (WinDivert)', _useWindivert,
                          (v) => setState(() => _useWindivert = v),
                          info: 'Intercept packets directly in the Windows TCP/IP stack via '
                              'WinDivert instead of passively tapping with pcap. This is how '
                              'Suricata/Snort run in IPS mode on Windows. Requires admin and '
                              'the WinDivert driver. Off = passive NIDS (pcap tap).'),
                      if (_useWindivert) ...[
                        const SizedBox(height: 8),
                        _buildToggle('Block flagged sources', _inlineBlock,
                            (v) => setState(() => _inlineBlock = v),
                            info: 'IPS enforcement: once a source IP triggers a threat '
                                '(port scan, flood, or LLM-confirmed attack), drop all its '
                                'subsequent packets from the stack. Off = detect/alert only.'),
                        const SizedBox(height: 8),
                        _buildFilterField(),
                        if (_inlineBlock) ...[
                          const SizedBox(height: 8),
                          _buildAllowlistField(),
                        ],
                      ],
                    ], info: 'How Wirewolf sees traffic: a passive tap (pcap) or inline in '
                        'the stack (WinDivert), which also enables active blocking.'),
                    const SizedBox(height: 16),
                    _buildSection('Advanced', [
                      _buildDropdown('Log Level', ['DEBUG', 'INFO', 'WARN', 'ERROR'], _logLevel,
                          (v) => setState(() => _logLevel = v),
                          info: 'Verbosity of the Log tab. DEBUG shows every flow decision; '
                              'INFO (default) shows alerts and milestones; WARN/ERROR show '
                              'only problems.'),
                      const SizedBox(height: 8),
                      _buildNumberField('GPU Layers', _gpuLayers, (v) => setState(() => _gpuLayers = v),
                          info: 'How many LLM layers to offload to the GPU. 99 = all layers '
                              '(fastest, needs enough VRAM). Lower this if you run out of GPU '
                              'memory — remaining layers run on CPU (slower).'),
                      const SizedBox(height: 8),
                      _buildNumberField('Context Size', _contextSize, (v) => setState(() => _contextSize = v),
                          info: 'Max tokens the LLM holds at once (prompt + payload + output). '
                              '8192 is typical. Larger uses more VRAM; must be big enough for '
                              'the system prompt plus the analyzed payload.'),
                    ], info: 'LLM runtime and logging options.'),
                    const SizedBox(height: 16),
                    _buildSection('Threat Intelligence', [
                      _buildFolderField(),
                    ], info: 'Load updatable detection rules from a folder: bad JA3 '
                        'fingerprints, C2/phishing domains, known-bad IPs, and content '
                        'signatures. Lets you refresh detection from threat-intel feeds '
                        '(abuse.ch, Emerging Threats) without recompiling — like Snort/'
                        'Suricata rule files.'),
                  ],
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildPipelineControl() {
    final stateColor = switch (widget.pipelineState) {
      PipelineState.running => AppColors.success,
      PipelineState.starting => AppColors.warning,
      PipelineState.stopping => AppColors.warning,
      PipelineState.error => AppColors.error,
      PipelineState.stopped => AppColors.textMuted,
    };
    final stateText = widget.pipelineState.name.toUpperCase();

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            Container(
              width: 8, height: 8,
              decoration: BoxDecoration(color: stateColor, shape: BoxShape.circle),
            ),
            const SizedBox(width: 8),
            Text('Pipeline: $stateText',
                style: TextStyle(color: stateColor, fontSize: 11, fontWeight: FontWeight.w600)),
            const Spacer(),
            if (!_isRunning)
              _actionButton('Start Pipeline', AppColors.success, _applyAndStart)
            else
              _actionButton('Stop Pipeline', AppColors.error, widget.onStop),
          ],
        ),
      ),
    );
  }

  Widget _actionButton(String label, Color color, VoidCallback onTap) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(4),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
        decoration: BoxDecoration(
          color: color.withOpacity(0.15),
          borderRadius: BorderRadius.circular(4),
          border: Border.all(color: color.withOpacity(0.3)),
        ),
        child: Text(label, style: TextStyle(color: color, fontSize: 11, fontWeight: FontWeight.w600)),
      ),
    );
  }

  // Small info icon with a tooltip explaining a setting.
  Widget _infoIcon(String message) {
    return Tooltip(
      message: message,
      preferBelow: true,
      waitDuration: const Duration(milliseconds: 150),
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
      margin: const EdgeInsets.symmetric(horizontal: 24),
      textStyle: const TextStyle(
        color: AppColors.textPrimary, fontSize: 11, height: 1.45,
      ),
      decoration: BoxDecoration(
        color: AppColors.surfaceLight,
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: AppColors.border),
      ),
      child: const Padding(
        padding: EdgeInsets.only(left: 5),
        child: Icon(Icons.help_outline, size: 12, color: AppColors.textMuted),
      ),
    );
  }

  // A label with an optional trailing info icon.
  Widget _label(String text, [String? info]) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Text(text, style: const TextStyle(color: AppColors.textSecondary, fontSize: 10)),
        if (info != null) _infoIcon(info),
      ],
    );
  }

  Widget _buildSection(String title, List<Widget> children, {String? info}) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Text(title, style: const TextStyle(color: AppColors.textSecondary, fontSize: 11, fontWeight: FontWeight.w500)),
                if (info != null) _infoIcon(info),
              ],
            ),
            const SizedBox(height: 12),
            ...children,
          ],
        ),
      ),
    );
  }

  Widget _buildInterfaceDropdown() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            _label('Interface',
                'The network adapter to capture live traffic from. '
                'Requires administrator privileges to enumerate and capture. '
                'Leave unset and use a PCAP file instead for offline analysis.'),
            const Spacer(),
            InkWell(
              onTap: _loadInterfaces,
              child: const Text('Refresh', style: TextStyle(color: AppColors.accent, fontSize: 10)),
            ),
          ],
        ),
        const SizedBox(height: 4),
        Container(
          height: 32,
          padding: const EdgeInsets.symmetric(horizontal: 8),
          decoration: BoxDecoration(
            color: AppColors.surfaceLight,
            borderRadius: BorderRadius.circular(4),
            border: Border.all(color: AppColors.border),
          ),
          child: DropdownButtonHideUnderline(
            child: DropdownButton<int>(
              isExpanded: true,
              value: _selectedInterface >= 0 ? _selectedInterface : null,
              hint: const Text('Select...', style: TextStyle(color: AppColors.textMuted, fontSize: 10)),
              dropdownColor: AppColors.surface,
              style: const TextStyle(color: AppColors.textPrimary, fontSize: 10),
              items: _interfaces.asMap().entries.map((e) {
                final label = e.value.description.isNotEmpty
                    ? '${e.value.description} (${e.value.name})'
                    : e.value.name;
                return DropdownMenuItem(value: e.key, child: Text(label, overflow: TextOverflow.ellipsis));
              }).toList(),
              onChanged: _isRunning ? null : (v) {
                setState(() => _selectedInterface = v ?? -1);
                if (v != null && widget.service != null) {
                  widget.service!.setInterface(_interfaces[v].name);
                }
              },
            ),
          ),
        ),
        if (_interfaces.isEmpty)
          const Padding(
            padding: EdgeInsets.only(top: 4),
            child: Text('No interfaces found. Run as admin?',
                style: TextStyle(color: AppColors.warning, fontSize: 9)),
          ),
      ],
    );
  }

  Widget _buildFileField(String label, TextEditingController ctrl, List<String> extensions, {String? info}) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _label(label, info),
        const SizedBox(height: 4),
        Row(
          children: [
            Expanded(
              child: SizedBox(
                height: 30,
                child: TextField(
                  controller: ctrl,
                  enabled: !_isRunning,
                  style: const TextStyle(color: AppColors.textPrimary, fontSize: 10),
                  decoration: InputDecoration(
                    contentPadding: const EdgeInsets.symmetric(horizontal: 8, vertical: 0),
                    filled: true,
                    fillColor: AppColors.surfaceLight,
                    border: OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide(color: AppColors.border)),
                    enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide(color: AppColors.border)),
                    hintText: 'Path...',
                    hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 10),
                  ),
                ),
              ),
            ),
            const SizedBox(width: 6),
            InkWell(
              onTap: _isRunning ? null : () async {
                final result = await FilePicker.platform.pickFiles(
                  type: FileType.custom,
                  allowedExtensions: extensions,
                );
                if (result != null) {
                  ctrl.text = result.files.single.path ?? '';
                }
              },
              child: Container(
                height: 30,
                padding: const EdgeInsets.symmetric(horizontal: 10),
                alignment: Alignment.center,
                decoration: BoxDecoration(
                  color: AppColors.surfaceLight,
                  borderRadius: BorderRadius.circular(4),
                  border: Border.all(color: AppColors.border),
                ),
                child: const Text('Browse', style: TextStyle(color: AppColors.textSecondary, fontSize: 10)),
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildFilterField() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _label('WinDivert Filter',
            'Which packets to intercept, in WinDivert filter syntax. '
            '"tcp" = all TCP traffic. Examples: "tcp.DstPort == 80 or '
            'tcp.DstPort == 443", "outbound and tcp". Narrow this to reduce '
            'overhead on busy links.'),
        const SizedBox(height: 4),
        SizedBox(
          height: 30,
          child: TextField(
            controller: _filterController,
            enabled: !_isRunning,
            style: const TextStyle(color: AppColors.textPrimary, fontSize: 10, fontFamily: 'monospace'),
            decoration: InputDecoration(
              contentPadding: const EdgeInsets.symmetric(horizontal: 8, vertical: 0),
              filled: true,
              fillColor: AppColors.surfaceLight,
              border: OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide(color: AppColors.border)),
              enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide(color: AppColors.border)),
              hintText: 'tcp',
              hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 10),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildAllowlistField() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _label('Never-block allowlist',
            'Comma-separated IPs the IPS must NEVER block (gateway, DNS, domain '
            'controller). Critical safety rail: stops a spoofed-source attack '
            'from tricking the IPS into dropping your own infrastructure. '
            'Example: 192.168.1.1, 192.168.1.10'),
        const SizedBox(height: 4),
        SizedBox(
          height: 30,
          child: TextField(
            controller: _allowlistController,
            enabled: !_isRunning,
            style: const TextStyle(color: AppColors.textPrimary, fontSize: 10, fontFamily: 'monospace'),
            decoration: InputDecoration(
              contentPadding: const EdgeInsets.symmetric(horizontal: 8, vertical: 0),
              filled: true,
              fillColor: AppColors.surfaceLight,
              border: OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide(color: AppColors.border)),
              enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide(color: AppColors.border)),
              hintText: '192.168.1.1, 8.8.8.8',
              hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 10),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildFolderField() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _label('Rules Folder',
            'Folder containing bad_ja3.txt, bad_domains.txt, bad_ips.txt and '
            'signatures.txt. Loaded when the pipeline starts. Leave empty to '
            'use built-in detection only.'),
        const SizedBox(height: 4),
        Row(
          children: [
            Expanded(
              child: SizedBox(
                height: 30,
                child: TextField(
                  controller: _rulesController,
                  enabled: !_isRunning,
                  style: const TextStyle(color: AppColors.textPrimary, fontSize: 10),
                  decoration: InputDecoration(
                    contentPadding: const EdgeInsets.symmetric(horizontal: 8, vertical: 0),
                    filled: true,
                    fillColor: AppColors.surfaceLight,
                    border: OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide(color: AppColors.border)),
                    enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide(color: AppColors.border)),
                    hintText: 'rules folder...',
                    hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 10),
                  ),
                ),
              ),
            ),
            const SizedBox(width: 6),
            InkWell(
              onTap: _isRunning ? null : () async {
                final dir = await FilePicker.platform.getDirectoryPath();
                if (dir != null) setState(() => _rulesController.text = dir);
              },
              child: Container(
                height: 30,
                padding: const EdgeInsets.symmetric(horizontal: 10),
                alignment: Alignment.center,
                decoration: BoxDecoration(
                  color: AppColors.surfaceLight,
                  borderRadius: BorderRadius.circular(4),
                  border: Border.all(color: AppColors.border),
                ),
                child: const Text('Browse', style: TextStyle(color: AppColors.textSecondary, fontSize: 10)),
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildToggle(String label, bool value, ValueChanged<bool> onChanged, {String? info}) {
    return Row(
      children: [
        Transform.scale(
          scale: 0.6,
          child: Switch(
            value: value,
            onChanged: _isRunning ? null : onChanged,
            activeColor: AppColors.accent,
            materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
          ),
        ),
        const SizedBox(width: 4),
        _label(label, info),
      ],
    );
  }

  Widget _buildSlider(String label, double value, double min, double max, ValueChanged<double> onChanged, {String? info}) {
    return Row(
      children: [
        SizedBox(width: 110, child: _label(label, info)),
        Expanded(
          child: SliderTheme(
            data: SliderThemeData(
              trackHeight: 2,
              thumbShape: const RoundSliderThumbShape(enabledThumbRadius: 6),
              activeTrackColor: AppColors.accent,
              inactiveTrackColor: AppColors.surfaceLight,
              thumbColor: AppColors.accent,
              overlayShape: SliderComponentShape.noOverlay,
            ),
            child: Slider(value: value, min: min, max: max, onChanged: _isRunning ? null : onChanged),
          ),
        ),
        SizedBox(
          width: 40,
          child: Text(value.toStringAsFixed(2), style: const TextStyle(color: AppColors.textMuted, fontSize: 10, fontFamily: 'monospace'), textAlign: TextAlign.right),
        ),
      ],
    );
  }

  Widget _buildDropdown(String label, List<String> items, int value, ValueChanged<int> onChanged, {String? info}) {
    return Row(
      children: [
        SizedBox(width: 110, child: _label(label, info)),
        Container(
          height: 28,
          padding: const EdgeInsets.symmetric(horizontal: 8),
          decoration: BoxDecoration(
            color: AppColors.surfaceLight,
            borderRadius: BorderRadius.circular(4),
            border: Border.all(color: AppColors.border),
          ),
          child: DropdownButtonHideUnderline(
            child: DropdownButton<int>(
              value: value,
              dropdownColor: AppColors.surface,
              style: const TextStyle(color: AppColors.textPrimary, fontSize: 10),
              items: items.asMap().entries.map((e) => DropdownMenuItem(value: e.key, child: Text(e.value))).toList(),
              onChanged: _isRunning ? null : (v) => onChanged(v!),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildNumberField(String label, int value, ValueChanged<int> onChanged, {String? info}) {
    return Row(
      children: [
        SizedBox(width: 110, child: _label(label, info)),
        SizedBox(
          width: 80, height: 28,
          child: TextField(
            controller: TextEditingController(text: '$value'),
            enabled: !_isRunning,
            keyboardType: TextInputType.number,
            style: const TextStyle(color: AppColors.textPrimary, fontSize: 10),
            decoration: InputDecoration(
              contentPadding: const EdgeInsets.symmetric(horizontal: 8, vertical: 0),
              filled: true,
              fillColor: AppColors.surfaceLight,
              border: OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide(color: AppColors.border)),
              enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide(color: AppColors.border)),
            ),
            onChanged: (s) { final v = int.tryParse(s); if (v != null) onChanged(v); },
          ),
        ),
      ],
    );
  }

  @override
  void dispose() {
    _interfaceController.dispose();
    _pcapController.dispose();
    _llamaController.dispose();
    _openvinoController.dispose();
    _filterController.dispose();
    _rulesController.dispose();
    _allowlistController.dispose();
    super.dispose();
  }
}
