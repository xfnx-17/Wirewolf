import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import '../ffi/wirewolf_service.dart';
import '../theme/app_theme.dart';

final _numFmt = NumberFormat.decimalPattern();

/// Most-targeted internal destinations, ranked by alert volume. Each row shows
/// a server-icon chip, the destination IP, its most-hit port, a neutral volume
/// bar and the count. Clicking a row selects that target's most recent alert in
/// the inspector. (Hostnames would need reverse-DNS; the IP stands in.)
class TopTargetsChart extends StatelessWidget {
  final List<AlertData> alerts;
  final int? selectedAlertIndex;
  final ValueChanged<int?>? onSelect;

  const TopTargetsChart({
    super.key,
    required this.alerts,
    this.selectedAlertIndex,
    this.onSelect,
  });

  @override
  Widget build(BuildContext context) {
    final agg = <String, _Tgt>{};
    for (var i = 0; i < alerts.length; i++) {
      final a = alerts[i];
      final t = agg.putIfAbsent(a.dstIp, () => _Tgt(a.dstIp));
      t.count++;
      t.lastIndex = i;
      t.ports[a.dstPort] = (t.ports[a.dstPort] ?? 0) + 1;
    }
    final targets = agg.values.toList()
      ..sort((a, b) => b.count.compareTo(a.count));
    final top = targets.take(5).toList();
    final maxVal = top.isEmpty ? 1 : top.first.count;

    final selectedIp = (selectedAlertIndex != null &&
            selectedAlertIndex! >= 0 &&
            selectedAlertIndex! < alerts.length)
        ? alerts[selectedAlertIndex!].dstIp
        : null;

    return Card(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(14, 12, 14, 10),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Text('Top Targets',
                    style: TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 13,
                        fontWeight: FontWeight.w700)),
                const Spacer(),
                if (onSelect != null)
                  const Text('click to inspect',
                      style:
                          TextStyle(color: AppColors.textMuted, fontSize: 11)),
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

  Widget _row(_Tgt t, int maxVal, bool selected) {
    final row = Padding(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
      child: Row(
        children: [
          Container(
            width: 28,
            height: 28,
            decoration: BoxDecoration(
              color: AppColors.surfaceLight,
              borderRadius: BorderRadius.circular(7),
            ),
            child: const Icon(Icons.dns_outlined,
                size: 15, color: AppColors.textMuted),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(t.ip,
                    style: AppText.mono(
                        size: 13,
                        weight: FontWeight.w700,
                        color: AppColors.textPrimary),
                    overflow: TextOverflow.ellipsis),
                Text(t.portLabel,
                    style: const TextStyle(
                        color: AppColors.textMuted, fontSize: 10.5),
                    overflow: TextOverflow.ellipsis),
              ],
            ),
          ),
          const SizedBox(width: 10),
          _bar(t.count / maxVal),
          const SizedBox(width: 12),
          Text(_numFmt.format(t.count),
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
        color:
            selected ? AppColors.accent.withOpacity(0.07) : Colors.transparent,
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
      onTap: () => onSelect!(t.lastIndex),
      borderRadius: BorderRadius.circular(10),
      child: content,
    );
  }

  Widget _bar(double frac) {
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
                color: AppColors.chart5,
                borderRadius: BorderRadius.circular(4),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _Tgt {
  final String ip;
  int count = 0;
  int lastIndex = 0;
  final Map<int, int> ports = {};
  _Tgt(this.ip);

  String get portLabel {
    if (ports.isEmpty) return '';
    if (ports.length > 1) return '${ports.length} ports';
    int best = ports.keys.first;
    return 'port $best';
  }
}
