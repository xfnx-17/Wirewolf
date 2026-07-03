import 'package:flutter/material.dart';
import '../ffi/wirewolf_service.dart';
import '../ffi/geo_ip.dart';
import '../theme/app_theme.dart';

/// Host-centric telemetry popup, reused by the dashboard's Top Targets panel
/// and the Threat Map side list. Shows the same enrichment as the Alert
/// Inspector (location, ISP/ASN, anonymizer, threat-intel tag) pivoted around a
/// single IP, plus its attacker/target role counts and the threat types it's
/// involved in.
void showHostTelemetry(
    BuildContext context, String ip, List<AlertData> alerts) {
  final atkCount = alerts.where((a) => a.srcIp == ip).length;
  final tgtCount = alerts.where((a) => a.dstIp == ip).length;
  final threats = alerts
      .where((a) => a.srcIp == ip || a.dstIp == ip)
      .map((a) => a.threatType)
      .toSet()
      .toList();
  final geo = endpointGeoFor(ip);
  final isExternal = geoForIp(ip) != null;
  final tag = threatTagFor(ip);

  showDialog<void>(
    context: context,
    builder: (ctx) => AlertDialog(
      backgroundColor: AppColors.surface,
      title: Row(
        children: [
          Icon(isExternal ? Icons.public : Icons.lan_outlined,
              size: 18, color: AppColors.accent),
          const SizedBox(width: 8),
          Expanded(
            child: Text(ip,
                style: AppText.mono(
                    size: 14,
                    weight: FontWeight.w700,
                    color: AppColors.textPrimary)),
          ),
        ],
      ),
      content: SizedBox(
        width: 380,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _telRow('Location', placeLabel(geo)),
            _telRow('ISP / ASN', isExternal ? ispLabelFor(ip) : '—'),
            _telRow('Anonymizer', isExternal ? anonLabelFor(ip) : 'No'),
            _telRow('Threat Intel', tag.isEmpty ? 'Clean' : tag,
                danger: tag.isNotEmpty),
            const Divider(height: 22, color: AppColors.border),
            _telRow('As attacker (source)', '$atkCount alert(s)',
                danger: atkCount > 0),
            _telRow('As target (destination)', '$tgtCount alert(s)',
                accent: tgtCount > 0),
            const SizedBox(height: 12),
            const Text('Threat types',
                style: TextStyle(
                    color: AppColors.textSecondary,
                    fontSize: 11,
                    fontWeight: FontWeight.w600)),
            const SizedBox(height: 6),
            Wrap(
              spacing: 6,
              runSpacing: 6,
              children: threats
                  .map((t) => Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 8, vertical: 3),
                        decoration: BoxDecoration(
                          color: AppColors.surfaceLight,
                          borderRadius: BorderRadius.circular(5),
                          border: Border.all(color: AppColors.border),
                        ),
                        child: Text(t,
                            style: AppText.mono(
                                size: 10, color: AppColors.textSecondary)),
                      ))
                  .toList(),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(ctx).pop(),
          child: const Text('Close'),
        ),
      ],
    ),
  );
}

Widget _telRow(String label, String value,
    {bool danger = false, bool accent = false}) {
  return Padding(
    padding: const EdgeInsets.symmetric(vertical: 4),
    child: Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 150,
          child: Text(label,
              style:
                  const TextStyle(color: AppColors.textMuted, fontSize: 11.5)),
        ),
        Expanded(
          child: Text(value,
              style: AppText.mono(
                  size: 11.5,
                  weight: FontWeight.w600,
                  color: danger
                      ? AppColors.error
                      : (accent ? AppColors.accent : AppColors.textPrimary))),
        ),
      ],
    ),
  );
}
