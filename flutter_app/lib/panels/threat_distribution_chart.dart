import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import '../ffi/wirewolf_service.dart';
import '../theme/app_theme.dart';

final _numFmt = NumberFormat.decimalPattern();

class ThreatDistributionChart extends StatelessWidget {
  final List<AlertData> alerts;

  const ThreatDistributionChart({super.key, required this.alerts});

  @override
  Widget build(BuildContext context) {
    final counts = <String, int>{};
    for (final a in alerts) {
      counts[a.threatType] = (counts[a.threatType] ?? 0) + 1;
    }
    final sorted = counts.entries.toList()
      ..sort((a, b) => b.value.compareTo(a.value));
    final top = sorted.take(6).toList();
    final maxVal = top.isEmpty ? 1 : top.first.value;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Threat Distribution',
              style: TextStyle(color: AppColors.textSecondary, fontSize: 11, fontWeight: FontWeight.w500),
            ),
            const SizedBox(height: 12),
            if (top.isEmpty)
              const Expanded(
                child: Center(child: Text('—', style: TextStyle(color: AppColors.textMuted))),
              )
            else
              ...top.asMap().entries.map((e) {
                final pct = e.value.value / maxVal;
                return Padding(
                  padding: const EdgeInsets.only(bottom: 6),
                  child: Row(
                    children: [
                      SizedBox(
                        width: 100,
                        child: Text(
                          e.value.key,
                          style: const TextStyle(color: AppColors.textSecondary, fontSize: 10),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      const SizedBox(width: 6),
                      Expanded(
                        child: ClipRRect(
                          borderRadius: BorderRadius.circular(1),
                          child: LinearProgressIndicator(
                            value: pct,
                            backgroundColor: AppColors.surfaceLight,
                            valueColor: AlwaysStoppedAnimation(AppColors.accent.withOpacity(0.6)),
                            minHeight: 12,
                          ),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Text(
                        _numFmt.format(e.value.value),
                        maxLines: 1,
                        softWrap: false,
                        overflow: TextOverflow.visible,
                        style: const TextStyle(color: AppColors.textSecondary, fontSize: 10, fontWeight: FontWeight.w600),
                      ),
                    ],
                  ),
                );
              }),
          ],
        ),
      ),
    );
  }
}
