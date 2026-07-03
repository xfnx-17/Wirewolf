import 'package:flutter/material.dart';
import '../ffi/wirewolf_service.dart';
import '../theme/app_theme.dart';

class FilterFunnelChart extends StatelessWidget {
  final StatsData? stats;

  const FilterFunnelChart({super.key, required this.stats});

  @override
  Widget build(BuildContext context) {
    final total = stats?.totalFlows ?? 0;
    final passed = stats?.filterPassed ?? 0;
    final alerts = stats?.alertsFired ?? 0;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Pipeline',
              style: TextStyle(color: AppColors.textSecondary, fontSize: 11, fontWeight: FontWeight.w500),
            ),
            const SizedBox(height: 14),
            _row('Total Flows', total, total, AppColors.accent),
            const SizedBox(height: 10),
            _row('Passed Filter', passed, total, AppColors.warning,
                note: total > 0 ? '${((total - passed) / total * 100).toStringAsFixed(0)}% filtered' : null),
            const SizedBox(height: 10),
            _row('Alerts', alerts, total, AppColors.critical,
                note: passed > 0 ? '${((passed - alerts) / passed * 100).toStringAsFixed(0)}% benign' : null),
          ],
        ),
      ),
    );
  }

  Widget _row(String label, int value, int max, Color color, {String? note}) {
    final pct = max > 0 ? value / max : 0.0;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(label, style: const TextStyle(color: AppColors.textSecondary, fontSize: 10)),
            Row(
              children: [
                Text(_fmt(value), style: TextStyle(color: color, fontSize: 11, fontWeight: FontWeight.w600)),
                if (note != null) ...[
                  const SizedBox(width: 6),
                  Text(note, style: const TextStyle(color: AppColors.textMuted, fontSize: 9)),
                ],
              ],
            ),
          ],
        ),
        const SizedBox(height: 3),
        ClipRRect(
          borderRadius: BorderRadius.circular(1),
          child: LinearProgressIndicator(
            value: pct.clamp(0.0, 1.0),
            backgroundColor: AppColors.surfaceLight,
            valueColor: AlwaysStoppedAnimation(color.withOpacity(0.5)),
            minHeight: 5,
          ),
        ),
      ],
    );
  }

  String _fmt(int n) {
    if (n >= 1000000) return '${(n / 1000000).toStringAsFixed(1)}M';
    if (n >= 1000) return '${(n / 1000).toStringAsFixed(1)}K';
    return n.toString();
  }
}
