import 'package:flutter/material.dart';
import '../ffi/wirewolf_service.dart';
import '../theme/app_theme.dart';

/// 28px accent-blue status bar pinned to the bottom of the window. Shows the
/// live pipeline state plus rolled-up ingest counters from the backend stats.
class StatusBar extends StatelessWidget {
  final PipelineState pipelineState;
  final StatsData? stats;
  final int alertCount;

  const StatusBar({
    super.key,
    required this.pipelineState,
    required this.stats,
    required this.alertCount,
  });

  @override
  Widget build(BuildContext context) {
    final s = stats;
    return Container(
      height: 28,
      color: AppColors.accent,
      padding: const EdgeInsets.symmetric(horizontal: 14),
      child: Row(
        children: [
          Icon(
            switch (pipelineState) {
              PipelineState.running => Icons.play_circle_fill,
              PipelineState.starting ||
              PipelineState.stopping =>
                Icons.hourglass_top,
              PipelineState.error => Icons.error,
              PipelineState.stopped => Icons.stop_circle,
            },
            size: 13,
            color: Colors.white,
          ),
          const SizedBox(width: 6),
          _item(pipelineState.name.toUpperCase()),
          _sep(),
          _item('${s?.filterDevice ?? 'Statistical'} filter'),
          _sep(),
          _item('${_fmt(s?.totalFlows ?? 0)} flows'),
          _sep(),
          _item('${_fmt(s?.filterPassed ?? 0)} → LLM'),
          _sep(),
          _item('$alertCount alerts'),
          if ((s?.blockedSources ?? 0) > 0) ...[
            _sep(),
            _item('${s!.blockedSources} blocked'),
          ],
          const Spacer(),
          _item('Wirewolf v1.0'),
        ],
      ),
    );
  }

  Widget _item(String text) => Text(text,
      style: AppText.mono(
          size: 10.5,
          weight: FontWeight.w500,
          color: Colors.white.withOpacity(0.95)));

  Widget _sep() => Padding(
        padding: const EdgeInsets.symmetric(horizontal: 10),
        child: Container(width: 1, height: 12, color: Colors.white24),
      );

  String _fmt(int n) {
    if (n >= 1000000) return '${(n / 1000000).toStringAsFixed(1)}M';
    if (n >= 1000) return '${(n / 1000).toStringAsFixed(1)}k';
    return n.toString();
  }
}
