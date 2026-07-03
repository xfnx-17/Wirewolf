import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import '../ffi/wirewolf_service.dart';
import '../theme/app_theme.dart';

final _numFmt = NumberFormat.decimalPattern();

/// Top attacking source IPs, ranked by alert volume. Each row shows a severity
/// dot, the IP, the source's dominant threat category, a severity-coloured
/// volume bar and the count. Clicking a row selects that source's most recent
/// alert in the inspector.
class TopSourcesChart extends StatelessWidget {
  final List<AlertData> alerts;
  final int? selectedAlertIndex;
  final ValueChanged<int?>? onSelect;

  const TopSourcesChart({
    super.key,
    required this.alerts,
    this.selectedAlertIndex,
    this.onSelect,
  });

  @override
  Widget build(BuildContext context) {
    // Aggregate per source IP.
    final agg = <String, _Src>{};
    for (var i = 0; i < alerts.length; i++) {
      final a = alerts[i];
      final s = agg.putIfAbsent(a.srcIp, () => _Src(a.srcIp));
      s.count++;
      s.lastIndex = i;
      if (a.severityLevel > s.worstSev) s.worstSev = a.severityLevel;
      s.types[a.threatType] = (s.types[a.threatType] ?? 0) + 1;
    }
    final sources = agg.values.toList()
      ..sort((a, b) => b.count.compareTo(a.count));
    final top = sources.take(5).toList();
    final maxVal = top.isEmpty ? 1 : top.first.count;

    final selectedIp = (selectedAlertIndex != null &&
            selectedAlertIndex! >= 0 &&
            selectedAlertIndex! < alerts.length)
        ? alerts[selectedAlertIndex!].srcIp
        : null;

    return Card(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(14, 12, 14, 10),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Text('Top Source IPs',
                    style: TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 13,
                        fontWeight: FontWeight.w700)),
                const Spacer(),
                if (onSelect != null)
                  const Text('click to inspect',
                      style: TextStyle(
                          color: AppColors.textMuted, fontSize: 11)),
              ],
            ),
            const SizedBox(height: 8),
            if (top.isEmpty)
              const Expanded(
                child: Center(
                    child: Text('—',
                        style: TextStyle(color: AppColors.textMuted))),
              )
            else
              Expanded(
                child: ListView.separated(
                  padding: EdgeInsets.zero,
                  itemCount: top.length,
                  separatorBuilder: (_, __) => const SizedBox(height: 2),
                  itemBuilder: (context, i) =>
                      _row(top[i], maxVal, top[i].ip == selectedIp),
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _row(_Src s, int maxVal, bool selected) {
    final color = AppColors.severityColor(s.worstSev);
    final tag = s.dominantType;
    final row = Padding(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
      child: Row(
        children: [
          Container(
            width: 8,
            height: 8,
            decoration: BoxDecoration(color: color, shape: BoxShape.circle),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(s.ip,
                    style: AppText.mono(
                        size: 13,
                        weight: FontWeight.w700,
                        color: AppColors.textPrimary),
                    overflow: TextOverflow.ellipsis),
                if (tag.isNotEmpty)
                  Text(tag,
                      style: const TextStyle(
                          color: AppColors.textMuted, fontSize: 10.5),
                      overflow: TextOverflow.ellipsis),
              ],
            ),
          ),
          const SizedBox(width: 10),
          _bar(s.count / maxVal, color),
          const SizedBox(width: 12),
          Text(_numFmt.format(s.count),
              maxLines: 1,
              softWrap: false,
              overflow: TextOverflow.visible,
              style: AppText.mono(
                  size: 14,
                  weight: FontWeight.w700,
                  color: AppColors.textPrimary)),
        ],
      ),
    );

    final content = DecoratedBox(
      decoration: BoxDecoration(
        color: selected ? AppColors.accent.withOpacity(0.07) : Colors.transparent,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(
            color: selected
                ? AppColors.accent.withOpacity(0.22)
                : Colors.transparent),
      ),
      child: row,
    );

    if (onSelect == null) return content;
    return InkWell(
      onTap: () => onSelect!(s.lastIndex),
      borderRadius: BorderRadius.circular(10),
      child: content,
    );
  }

  Widget _bar(double frac, Color color) {
    return SizedBox(
      width: 96,
      height: 8,
      child: Stack(
        children: [
          Container(
            decoration: BoxDecoration(
              color: AppColors.background,
              borderRadius: BorderRadius.circular(4),
            ),
          ),
          FractionallySizedBox(
            widthFactor: frac.clamp(0.06, 1.0),
            child: Container(
              decoration: BoxDecoration(
                color: color,
                borderRadius: BorderRadius.circular(4),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _Src {
  final String ip;
  int count = 0;
  int worstSev = 0;
  int lastIndex = 0;
  final Map<String, int> types = {};
  _Src(this.ip);

  String get dominantType {
    if (types.isEmpty) return '';
    String best = '';
    int bestN = -1;
    types.forEach((k, v) {
      if (v > bestN) {
        bestN = v;
        best = k;
      }
    });
    return best;
  }
}
