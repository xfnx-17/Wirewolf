import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';
import '../ffi/wirewolf_service.dart';
import '../theme/app_theme.dart';

class AlertsTimelineChart extends StatelessWidget {
  final List<AlertData> alerts;

  const AlertsTimelineChart({super.key, required this.alerts});

  @override
  Widget build(BuildContext context) {
    final buckets = _bucketAlerts();

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Alerts Timeline',
              style: TextStyle(color: AppColors.textSecondary, fontSize: 11, fontWeight: FontWeight.w500),
            ),
            const SizedBox(height: 12),
            Expanded(
              child: buckets.isEmpty
                  ? const Center(child: Text('—', style: TextStyle(color: AppColors.textMuted)))
                  : BarChart(
                      BarChartData(
                        barGroups: buckets.asMap().entries.map((e) {
                          return BarChartGroupData(
                            x: e.key,
                            barRods: [
                              BarChartRodData(
                                toY: e.value.total.toDouble(),
                                width: 10,
                                borderRadius: const BorderRadius.vertical(top: Radius.circular(2)),
                                rodStackItems: _buildStack(e.value),
                                color: Colors.transparent,
                              ),
                            ],
                          );
                        }).toList(),
                        borderData: FlBorderData(show: false),
                        barTouchData: BarTouchData(
                          touchTooltipData: BarTouchTooltipData(
                            getTooltipColor: (_) => AppColors.surfaceLight,
                            tooltipBorder: const BorderSide(color: AppColors.border),
                            tooltipRoundedRadius: 6,
                            tooltipPadding: const EdgeInsets.symmetric(horizontal: 8, vertical: 5),
                            getTooltipItem: (group, groupIdx, rod, rodIdx) {
                              final b = buckets[group.x];
                              return BarTooltipItem(
                                '${b.total.toInt()} alerts\n',
                                const TextStyle(
                                  color: AppColors.textPrimary,
                                  fontSize: 11,
                                  fontWeight: FontWeight.w600,
                                ),
                                children: [
                                  TextSpan(
                                    text: b.label,
                                    style: const TextStyle(
                                      color: AppColors.textMuted,
                                      fontSize: 9,
                                      fontWeight: FontWeight.normal,
                                    ),
                                  ),
                                ],
                              );
                            },
                          ),
                        ),
                        gridData: FlGridData(
                          show: true,
                          drawVerticalLine: false,
                          getDrawingHorizontalLine: (value) => FlLine(color: AppColors.border, strokeWidth: 0.3),
                        ),
                        titlesData: FlTitlesData(
                          leftTitles: AxisTitles(
                            sideTitles: SideTitles(
                              showTitles: true,
                              reservedSize: 22,
                              getTitlesWidget: (v, _) => Text(
                                v.toInt().toString(),
                                style: const TextStyle(color: AppColors.textMuted, fontSize: 9),
                              ),
                            ),
                          ),
                          bottomTitles: AxisTitles(
                            sideTitles: SideTitles(
                              showTitles: true,
                              getTitlesWidget: (v, _) {
                                final idx = v.toInt();
                                if (idx < 0 || idx >= buckets.length) return const SizedBox();
                                return Text(
                                  buckets[idx].label,
                                  style: const TextStyle(color: AppColors.textMuted, fontSize: 8),
                                );
                              },
                            ),
                          ),
                          topTitles: const AxisTitles(sideTitles: SideTitles(showTitles: false)),
                          rightTitles: const AxisTitles(sideTitles: SideTitles(showTitles: false)),
                        ),
                      ),
                    ),
            ),
          ],
        ),
      ),
    );
  }

  List<BarChartRodStackItem> _buildStack(_Bucket b) {
    final items = <BarChartRodStackItem>[];
    double y = 0;
    if (b.critical > 0) {
      items.add(BarChartRodStackItem(y, y + b.critical, AppColors.critical.withOpacity(0.7)));
      y += b.critical;
    }
    if (b.high > 0) {
      items.add(BarChartRodStackItem(y, y + b.high, AppColors.high.withOpacity(0.7)));
      y += b.high;
    }
    if (b.medium > 0) {
      items.add(BarChartRodStackItem(y, y + b.medium, AppColors.medium.withOpacity(0.7)));
      y += b.medium;
    }
    if (b.low > 0) {
      items.add(BarChartRodStackItem(y, y + b.low, AppColors.low.withOpacity(0.5)));
      y += b.low;
    }
    return items;
  }

  List<_Bucket> _bucketAlerts() {
    if (alerts.isEmpty) return [];
    final sorted = [...alerts]..sort((a, b) => a.timestamp.compareTo(b.timestamp));
    final start = sorted.first.timestamp;
    final end = sorted.last.timestamp;
    final range = end.difference(start);
    final bucketDuration = range.inSeconds > 0
        ? Duration(seconds: (range.inSeconds / 12).ceil().clamp(1, 999999))
        : const Duration(minutes: 1);

    final buckets = <_Bucket>[];
    var bucketStart = start;
    while (bucketStart.isBefore(end) || buckets.isEmpty) {
      final bucketEnd = bucketStart.add(bucketDuration);
      final inBucket = sorted.where(
          (a) => !a.timestamp.isBefore(bucketStart) && a.timestamp.isBefore(bucketEnd));
      final b = _Bucket(label: '${bucketStart.hour}:${bucketStart.minute.toString().padLeft(2, '0')}');
      for (final a in inBucket) {
        switch (a.severityLevel) {
          case 4: b.critical++;
          case 3: b.high++;
          case 2: b.medium++;
          default: b.low++;
        }
      }
      buckets.add(b);
      bucketStart = bucketEnd;
      if (buckets.length >= 12) break;
    }
    return buckets;
  }
}

class _Bucket {
  final String label;
  double critical = 0, high = 0, medium = 0, low = 0;
  _Bucket({required this.label});
  double get total => critical + high + medium + low;
}
