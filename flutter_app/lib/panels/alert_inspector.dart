import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import '../ffi/wirewolf_service.dart';
import '../ffi/geo_ip.dart';
import '../theme/app_theme.dart';
import '../util/incident_report.dart';

/// 316px right-rail Alert Inspector. Shows the selected alert's identity,
/// severity, a confidence bar, a key/value field grid, the matched snippet and
/// raw LLM output, plus analyst action buttons.
class AlertInspector extends StatelessWidget {
  final AlertData? alert;
  final int? alertNumber;
  final VoidCallback? onAcknowledge;
  final VoidCallback? onMute;
  final bool collapsed;
  final VoidCallback? onToggleCollapse;

  const AlertInspector({
    super.key,
    required this.alert,
    this.alertNumber,
    this.onAcknowledge,
    this.onMute,
    this.collapsed = false,
    this.onToggleCollapse,
  });

  @override
  Widget build(BuildContext context) {
    if (collapsed) return _collapsed();
    return Container(
      width: 316,
      decoration: const BoxDecoration(
        color: AppColors.surface,
        border: Border(left: BorderSide(color: AppColors.border, width: 1)),
      ),
      child: Column(
        children: [
          _collapseHandle(),
          const Divider(height: 1, color: AppColors.hairline),
          Expanded(child: alert == null ? _empty() : _content(alert!)),
        ],
      ),
    );
  }

  Widget _collapseHandle() {
    return SizedBox(
      height: 34,
      child: Row(
        children: [
          const SizedBox(width: 12),
          const Icon(Icons.fact_check_outlined,
              size: 14, color: AppColors.textMuted),
          const SizedBox(width: 6),
          Text('INSPECTOR',
              style: AppText.mono(
                  size: 10,
                  weight: FontWeight.w700,
                  color: AppColors.textMuted,
                  letterSpacing: 0.5)),
          const Spacer(),
          InkWell(
            onTap: onToggleCollapse,
            borderRadius: BorderRadius.circular(4),
            child: const Padding(
              padding: EdgeInsets.all(8),
              child: Icon(Icons.chevron_right,
                  size: 16, color: AppColors.textMuted),
            ),
          ),
        ],
      ),
    );
  }

  Widget _collapsed() {
    return InkWell(
      onTap: onToggleCollapse,
      child: Container(
        width: 40,
        decoration: const BoxDecoration(
          color: AppColors.surface,
          border: Border(left: BorderSide(color: AppColors.border, width: 1)),
        ),
        child: Column(
          children: [
            const SizedBox(height: 11),
            const Icon(Icons.chevron_left, size: 18, color: AppColors.accent),
            const SizedBox(height: 12),
            if (alert != null)
              Container(
                width: 8,
                height: 8,
                decoration: BoxDecoration(
                  color: AppColors.severityColor(alert!.severityLevel),
                  shape: BoxShape.circle,
                ),
              ),
            Expanded(
              child: Center(
                child: RotatedBox(
                  quarterTurns: 3,
                  child: Text('ALERT INSPECTOR',
                      style: AppText.mono(
                          size: 10,
                          weight: FontWeight.w700,
                          color: AppColors.textMuted,
                          letterSpacing: 1.5)),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _empty() {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.travel_explore_outlined,
              size: 40, color: AppColors.textMuted.withOpacity(0.5)),
          const SizedBox(height: 12),
          const Text('Alert Inspector',
              style: TextStyle(
                  color: AppColors.textSecondary,
                  fontSize: 13,
                  fontWeight: FontWeight.w600)),
          const SizedBox(height: 4),
          const Text('Select an alert to inspect',
              style: TextStyle(color: AppColors.textMuted, fontSize: 11)),
        ],
      ),
    );
  }

  Widget _content(AlertData a) {
    final color = AppColors.severityColor(a.severityLevel);
    final timeFmt = DateFormat('yyyy-MM-dd HH:mm:ss');
    final conf = a.confidencePct;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // Header
        Container(
          padding: const EdgeInsets.fromLTRB(16, 14, 16, 12),
          decoration: const BoxDecoration(
            border: Border(bottom: BorderSide(color: AppColors.hairline)),
          ),
          child: Row(
            children: [
              Text(
                  'ALT-${(alertNumber ?? 0).toString().padLeft(4, '0')}',
                  style: AppText.mono(
                      size: 11,
                      weight: FontWeight.w700,
                      color: AppColors.textMuted)),
              const Spacer(),
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: color.withOpacity(0.12),
                  borderRadius: BorderRadius.circular(20),
                ),
                child: Text(a.severityLabel.toUpperCase(),
                    style: AppText.mono(
                        size: 10, weight: FontWeight.w700, color: color)),
              ),
            ],
          ),
        ),

        Expanded(
          child: SingleChildScrollView(
            padding: const EdgeInsets.fromLTRB(16, 14, 16, 14),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(a.threatType,
                    style: const TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 16,
                        fontWeight: FontWeight.w700)),
                const SizedBox(height: 3),
                Text('CVSS 4.0 ${a.cvss.toStringAsFixed(1)} · ${timeFmt.format(a.timestamp)}',
                    style: const TextStyle(
                        color: AppColors.textMuted, fontSize: 11)),
                const SizedBox(height: 12),
                ..._riskBanners(a),
                const SizedBox(height: 2),

                // Confidence bar
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    const Text('Confidence',
                        style: TextStyle(
                            color: AppColors.textSecondary, fontSize: 11)),
                    Text('$conf%',
                        style: AppText.mono(
                            size: 11,
                            weight: FontWeight.w700,
                            color: AppColors.textPrimary)),
                  ],
                ),
                const SizedBox(height: 6),
                ClipRRect(
                  borderRadius: BorderRadius.circular(3),
                  child: LinearProgressIndicator(
                    value: conf / 100,
                    minHeight: 6,
                    backgroundColor: AppColors.surfaceLight,
                    valueColor: AlwaysStoppedAnimation(color),
                  ),
                ),
                const SizedBox(height: 16),

                // Telemetry grid
                _telemetry(a),

                const SizedBox(height: 14),
                // Plain-English explanation of what this alert means.
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: AppColors.surfaceLight,
                    borderRadius: BorderRadius.circular(6),
                    border: Border.all(color: AppColors.border),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text('EXPLANATION',
                          style: TextStyle(
                              color: AppColors.textMuted,
                              fontSize: 10,
                              fontWeight: FontWeight.w700,
                              letterSpacing: 0.5)),
                      const SizedBox(height: 6),
                      Text(explainAlert(a),
                          style: const TextStyle(
                              color: AppColors.textSecondary,
                              fontSize: 12,
                              height: 1.4)),
                    ],
                  ),
                ),

                const SizedBox(height: 14),
                _codeBlock('Matched Snippet', a.snippet,
                    mono: true, color: AppColors.error),
                if (a.rawLlmOutput.isNotEmpty) ...[
                  const SizedBox(height: 12),
                  _codeBlock('LLM Output', a.rawLlmOutput,
                      mono: true, color: AppColors.textSecondary),
                ],
                if (a.payloadText.isNotEmpty &&
                    a.payloadText != a.snippet) ...[
                  const SizedBox(height: 12),
                  _codeBlock('Payload', a.payloadText,
                      mono: true,
                      color: AppColors.textSecondary,
                      maxHeight: 160),
                ],
              ],
            ),
          ),
        ),

        // Action buttons
        Container(
          padding: const EdgeInsets.all(12),
          decoration: const BoxDecoration(
            border: Border(top: BorderSide(color: AppColors.hairline)),
          ),
          child: Row(
            children: [
              Expanded(
                child: _actionButton(
                    'Acknowledge', AppColors.accent, true, onAcknowledge),
              ),
              const SizedBox(width: 8),
              _actionButton('Mute', AppColors.textSecondary, false, onMute,
                  icon: Icons.volume_off_outlined),
            ],
          ),
        ),
      ],
    );
  }

  // Threat-intel / anonymizer risk banners for the alert's external endpoint.
  // Threat-tagged IPs (curated malicious) are high-signal (red); anonymizers
  // (Tor/VPN) are risk context (amber). Neither is fabricated from "is a proxy".
  List<Widget> _riskBanners(AlertData a) {
    final ext = externalEndpoint(a.srcIp, a.dstIp);
    if (ext == null) return const [];
    final banners = <Widget>[];
    final tag = threatTagFor(ext.ip);
    if (tag.isNotEmpty) {
      banners.add(_banner(Icons.gpp_bad, AppColors.critical,
          'THREAT INTEL: $tag', '${ext.ip} is flagged malicious infrastructure'));
    }
    if (isAnonymizerIp(ext.ip)) {
      banners.add(_banner(Icons.vpn_lock, AppColors.warning, 'Anonymized origin',
          'Traffic via ${anonLabelFor(ext.ip)} — attribution obscured'));
    }
    return banners;
  }

  Widget _banner(IconData icon, Color color, String title, String sub) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
      decoration: BoxDecoration(
        color: color.withOpacity(0.10),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: color.withOpacity(0.35)),
      ),
      child: Row(
        children: [
          Icon(icon, size: 16, color: color),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title,
                    style: TextStyle(
                        color: color, fontSize: 11.5, fontWeight: FontWeight.w700)),
                Text(sub,
                    style: const TextStyle(
                        color: AppColors.textSecondary, fontSize: 10.5)),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _telemetry(AlertData a) {
    final ext = externalEndpoint(a.srcIp, a.dstIp);
    final geoLabel = ext != null ? placeLabel(ext.geo) : 'Internal (LAN)';
    final extIp = ext?.ip ?? '';
    final isp = ext != null ? ispLabelFor(extIp) : '—';
    final anon = ext != null ? anonLabelFor(extIp) : '—';
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('TELEMETRY',
            style: AppText.mono(
                size: 10,
                weight: FontWeight.w700,
                color: AppColors.textMuted,
                letterSpacing: 1.0)),
        const SizedBox(height: 10),
        _telRow('Source IP', a.srcIp, 'Geo', geoLabel),
        const SizedBox(height: 10),
        _telRow('Target IP', a.dstIp, 'Protocol', 'TCP / ${a.dstPort}'),
        const SizedBox(height: 10),
        _cell('ISP / ASN', isp), // full-width (names are long)
        const SizedBox(height: 10),
        _telRow('Anonymizer', anon, 'CVSS 4.0', a.cvss.toStringAsFixed(1)),
      ],
    );
  }

  Widget _telRow(String l1, String v1, String l2, String v2) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Expanded(child: _cell(l1, v1)),
        const SizedBox(width: 10),
        Expanded(child: _cell(l2, v2)),
      ],
    );
  }

  Widget _cell(String label, String value) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label,
            style: const TextStyle(
                color: AppColors.textMuted, fontSize: 11)),
        const SizedBox(height: 4),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 9),
          decoration: BoxDecoration(
            color: AppColors.surfaceLight,
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: AppColors.border),
          ),
          child: Text(value,
              style: AppText.mono(size: 12, color: AppColors.textPrimary),
              overflow: TextOverflow.ellipsis),
        ),
      ],
    );
  }

  Widget _codeBlock(String label, String text,
      {bool mono = false, required Color color, double? maxHeight}) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label,
            style: const TextStyle(
                color: AppColors.textMuted,
                fontSize: 10,
                fontWeight: FontWeight.w600,
                letterSpacing: 0.4)),
        const SizedBox(height: 6),
        Container(
          width: double.infinity,
          constraints: maxHeight != null
              ? BoxConstraints(maxHeight: maxHeight)
              : const BoxConstraints(),
          padding: const EdgeInsets.all(10),
          decoration: BoxDecoration(
            color: AppColors.surfaceLight,
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: AppColors.border),
          ),
          child: SingleChildScrollView(
            child: SelectableText(text,
                style: AppText.mono(size: 11, color: color, height: 1.45)),
          ),
        ),
      ],
    );
  }

  Widget _actionButton(
      String label, Color color, bool filled, VoidCallback? onTap,
      {IconData? icon}) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(8),
      child: Container(
        height: 34,
        padding: const EdgeInsets.symmetric(horizontal: 12),
        alignment: Alignment.center,
        decoration: BoxDecoration(
          color: filled ? color : Colors.transparent,
          borderRadius: BorderRadius.circular(8),
          border: filled ? null : Border.all(color: AppColors.border),
          boxShadow: filled
              ? [
                  BoxShadow(
                    color: color.withOpacity(0.28),
                    blurRadius: 10,
                    offset: const Offset(0, 2),
                  )
                ]
              : null,
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (icon != null) ...[
              Icon(icon, size: 14, color: filled ? Colors.white : color),
              const SizedBox(width: 6),
            ],
            Text(label,
                style: TextStyle(
                    color: filled ? Colors.white : color,
                    fontSize: 12,
                    fontWeight: FontWeight.w600)),
          ],
        ),
      ),
    );
  }

}
