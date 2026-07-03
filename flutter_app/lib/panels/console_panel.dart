import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import '../ffi/wirewolf_service.dart';
import '../theme/app_theme.dart';

/// 184px bottom console with ALERTS / EVENTS / OUTPUT / SYSTEM tabs, each fed
/// from live backend streams. Mirrors the redesign's terminal-style log strip.
class ConsolePanel extends StatefulWidget {
  final List<AlertData> alerts;
  final List<FlowEventData> flowEvents;
  final List<LogEntryData> logs;
  final bool collapsed;
  final VoidCallback onToggleCollapse;

  const ConsolePanel({
    super.key,
    required this.alerts,
    required this.flowEvents,
    required this.logs,
    required this.collapsed,
    required this.onToggleCollapse,
  });

  @override
  State<ConsolePanel> createState() => _ConsolePanelState();
}

class _ConsolePanelState extends State<ConsolePanel> {
  int _tab = 0;
  static const _tabs = ['ALERTS', 'EVENTS', 'OUTPUT', 'SYSTEM'];

  int _countFor(int tab) => switch (tab) {
        0 => widget.alerts.length,
        1 => widget.flowEvents.length,
        2 => widget.alerts.length,
        _ => widget.logs.length,
      };

  @override
  Widget build(BuildContext context) {
    return Container(
      height: widget.collapsed ? 34 : 184,
      decoration: const BoxDecoration(
        color: AppColors.surface,
        border: Border(top: BorderSide(color: AppColors.border, width: 1)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Tab strip
          Container(
            height: 34,
            padding: const EdgeInsets.symmetric(horizontal: 8),
            decoration: BoxDecoration(
              border: Border(
                  bottom: BorderSide(
                      color: widget.collapsed
                          ? Colors.transparent
                          : AppColors.hairline)),
            ),
            child: Row(
              children: [
                for (var i = 0; i < _tabs.length; i++) _tabButton(i),
                const Spacer(),
                Icon(Icons.terminal, size: 14, color: AppColors.textMuted),
                const SizedBox(width: 6),
                Text('console',
                    style: AppText.mono(size: 10, color: AppColors.textMuted)),
                const SizedBox(width: 8),
                InkWell(
                  onTap: widget.onToggleCollapse,
                  borderRadius: BorderRadius.circular(4),
                  child: Padding(
                    padding: const EdgeInsets.all(4),
                    child: Icon(
                        widget.collapsed
                            ? Icons.keyboard_arrow_up
                            : Icons.keyboard_arrow_down,
                        size: 16,
                        color: AppColors.textMuted),
                  ),
                ),
              ],
            ),
          ),
          if (!widget.collapsed) Expanded(child: _body()),
        ],
      ),
    );
  }

  Widget _tabButton(int i) {
    final active = _tab == i;
    return InkWell(
      onTap: () => setState(() => _tab = i),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12),
        decoration: BoxDecoration(
          border: Border(
            bottom: BorderSide(
              color: active ? AppColors.accent : Colors.transparent,
              width: 2,
            ),
          ),
        ),
        alignment: Alignment.center,
        child: Text('${_tabs[i]} ${_countFor(i)}',
            style: AppText.mono(
                size: 10.5,
                weight: FontWeight.w700,
                color: active ? AppColors.textPrimary : AppColors.textMuted,
                letterSpacing: 0.5)),
      ),
    );
  }

  Widget _body() {
    final lines = switch (_tab) {
      0 => _alertLines(),
      1 => _eventLines(),
      2 => _outputLines(),
      _ => _systemLines(),
    };
    if (lines.isEmpty) {
      return Center(
        child: Text('— no entries —',
            style: AppText.mono(size: 11, color: AppColors.textMuted)),
      );
    }
    return ListView.builder(
      reverse: true,
      padding: const EdgeInsets.symmetric(vertical: 4),
      itemCount: lines.length,
      itemBuilder: (context, index) => lines[lines.length - 1 - index],
    );
  }

  Widget _line(String time, String glyph, Color glyphColor, String message,
      {String? tag, Color? tagColor}) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 2),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 58,
            child: Text(time,
                style: AppText.mono(size: 10.5, color: AppColors.textMuted)),
          ),
          SizedBox(
            width: 16,
            child: Text(glyph,
                style: AppText.mono(
                    size: 11, weight: FontWeight.w700, color: glyphColor)),
          ),
          if (tag != null) ...[
            Container(
              margin: const EdgeInsets.only(right: 8, top: 1),
              padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
              decoration: BoxDecoration(
                color: (tagColor ?? glyphColor).withOpacity(0.12),
                borderRadius: BorderRadius.circular(4),
              ),
              child: Text(tag,
                  style: AppText.mono(
                      size: 9,
                      weight: FontWeight.w700,
                      color: tagColor ?? glyphColor)),
            ),
          ],
          Expanded(
            child: Text(message,
                style: AppText.mono(
                    size: 11, color: AppColors.textSecondary, height: 1.35)),
          ),
        ],
      ),
    );
  }

  final _t = DateFormat('HH:mm:ss');

  List<Widget> _alertLines() => widget.alerts
      .map((a) => _line(
            _t.format(a.timestamp),
            '⚠',
            AppColors.severityColor(a.severityLevel),
            '${a.threatType} — ${a.srcIp} → ${a.dstIp}:${a.dstPort}',
            tag: a.severityLabel.toUpperCase(),
            tagColor: AppColors.severityColor(a.severityLevel),
          ))
      .toList();

  List<Widget> _eventLines() => widget.flowEvents
      .map((e) => _line(
            _t.format(e.timestamp),
            switch (e.action) { 1 => '→', 2 => '✓', _ => '·' },
            switch (e.action) {
              1 => AppColors.warning,
              2 => AppColors.success,
              _ => AppColors.textMuted,
            },
            '${e.srcIp}:${e.srcPort} → ${e.dstIp}:${e.dstPort}  ${e.reason}',
          ))
      .toList();

  List<Widget> _outputLines() => widget.alerts
      .map((a) => _line(
            _t.format(a.timestamp),
            '>',
            AppColors.textMuted,
            a.rawLlmOutput,
          ))
      .toList();

  List<Widget> _systemLines() => widget.logs
      .map((l) => _line(
            _t.format(l.timestamp),
            switch (l.level) { 3 => '✕', 2 => '!', _ => '·' },
            switch (l.level) {
              3 => AppColors.error,
              2 => AppColors.warning,
              _ => AppColors.textMuted,
            },
            '[${l.component}] ${l.message}',
          ))
      .toList();
}
