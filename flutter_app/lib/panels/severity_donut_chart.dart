import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';
import '../ffi/wirewolf_service.dart';
import '../theme/app_theme.dart';

/// Severity breakdown donut with a centred alert total and a legend showing
/// per-severity counts and percentages.
class SeverityDonutChart extends StatelessWidget {
  final List<AlertData> alerts;

  const SeverityDonutChart({super.key, required this.alerts});

  @override
  Widget build(BuildContext context) {
    final counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0};
    for (final a in alerts) {
      counts[a.severityLabel] = (counts[a.severityLabel] ?? 0) + 1;
    }
    final total = alerts.length;

    final rows = <({String label, int count, Color color})>[
      (label: 'Critical', count: counts['Critical']!, color: AppColors.critical),
      (label: 'High', count: counts['High']!, color: AppColors.high),
      (label: 'Medium', count: counts['Medium']!, color: AppColors.medium),
      (label: 'Low', count: counts['Low']!, color: AppColors.low),
    ];

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Severity',
                style: TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 13,
                    fontWeight: FontWeight.w700)),
            const SizedBox(height: 8),
            Expanded(
              child: Row(
                children: [
                  // Donut + centred total
                  SizedBox(
                    width: 104,
                    child: Center(
                      child: SizedBox(
                        width: 100,
                        height: 100,
                        child: Stack(
                          alignment: Alignment.center,
                          children: [
                            PieChart(
                              PieChartData(
                                sectionsSpace: total == 0 ? 0 : 3,
                                centerSpaceRadius: 30,
                                startDegreeOffset: -90,
                                sections: total == 0
                                    ? [
                                        PieChartSectionData(
                                          value: 1,
                                          color: AppColors.background,
                                          radius: 16,
                                          showTitle: false,
                                        )
                                      ]
                                    : [
                                        for (final r in rows)
                                          if (r.count > 0)
                                            PieChartSectionData(
                                              value: r.count.toDouble(),
                                              color: r.color,
                                              radius: 14,
                                              showTitle: false,
                                            ),
                                      ],
                              ),
                            ),
                            Column(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Text('$total',
                                    style: AppText.mono(
                                        size: 22,
                                        weight: FontWeight.w700,
                                        color: AppColors.textPrimary)),
                                Text('ALERTS',
                                    style: TextStyle(
                                        color: AppColors.textMuted,
                                        fontSize: 9,
                                        letterSpacing: 1.2,
                                        fontWeight: FontWeight.w600)),
                              ],
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  // Legend
                  Expanded(
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        for (final r in rows) ...[
                          _legend(r.label, r.count, total, r.color),
                          const SizedBox(height: 10),
                        ],
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _legend(String label, int count, int total, Color color) {
    final pct = total > 0 ? (count / total * 100).round() : 0;
    return Row(
      children: [
        Container(
          width: 11,
          height: 11,
          decoration: BoxDecoration(
            color: color,
            borderRadius: BorderRadius.circular(3),
          ),
        ),
        const SizedBox(width: 8),
        Expanded(
          child: Text(label,
              maxLines: 1,
              softWrap: false,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(
                  color: AppColors.textSecondary, fontSize: 12)),
        ),
        const SizedBox(width: 4),
        Text('$count',
            style: AppText.mono(
                size: 12.5,
                weight: FontWeight.w700,
                color: AppColors.textPrimary)),
        SizedBox(
          width: 32,
          child: Text('$pct%',
              textAlign: TextAlign.right,
              style: const TextStyle(
                  color: AppColors.textMuted, fontSize: 11)),
        ),
      ],
    );
  }
}
