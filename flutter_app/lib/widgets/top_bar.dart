import 'package:flutter/material.dart';
import '../ffi/wirewolf_service.dart';
import '../theme/app_theme.dart';
import 'wirewolf_mark.dart';

/// 52px application top bar: brand on the left, a command-palette trigger in
/// the center, and live status + utility icons on the right.
class TopBar extends StatelessWidget {
  final VoidCallback onPaletteTap;
  final bool paletteOpen;
  final PipelineState pipelineState;
  final bool demoMode;
  final int alertCount;
  final VoidCallback? onClear;

  const TopBar({
    super.key,
    required this.onPaletteTap,
    required this.paletteOpen,
    required this.pipelineState,
    required this.demoMode,
    this.alertCount = 0,
    this.onClear,
  });

  bool get _live =>
      pipelineState == PipelineState.running ||
      pipelineState == PipelineState.starting;

  @override
  Widget build(BuildContext context) {
    return Container(
      height: 52,
      decoration: const BoxDecoration(
        color: AppColors.surface,
        border: Border(bottom: BorderSide(color: AppColors.border, width: 1)),
      ),
      padding: const EdgeInsets.symmetric(horizontal: 16),
      child: Row(
        children: [
          // Brand
          Container(
            width: 28,
            height: 28,
            decoration: BoxDecoration(
              color: const Color(0xFF0B0E12),
              borderRadius: BorderRadius.circular(8),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withOpacity(0.25),
                  blurRadius: 10,
                  offset: const Offset(0, 2),
                ),
              ],
            ),
            child: const Center(child: WirewolfMark(size: 18)),
          ),
          const SizedBox(width: 10),
          Text('WIREWOLF',
              style: AppText.mono(
                  size: 13,
                  weight: FontWeight.w700,
                  color: AppColors.textPrimary,
                  letterSpacing: 1.2)),
          const SizedBox(width: 8),
          const Text('— Network Threat Monitor',
              style: TextStyle(color: AppColors.textMuted, fontSize: 12)),

          // Command palette trigger
          const Spacer(),
          _PaletteTrigger(onTap: onPaletteTap, open: paletteOpen),
          const Spacer(),

          // Clear — wipes all accumulated alerts/events/logs so a fresh capture
          // doesn't show stale data from the previous pcap.
          if (onClear != null) ...[
            Tooltip(
              message: 'Clear all data (alerts, events, logs)',
              child: InkWell(
                onTap: alertCount == 0 ? null : onClear,
                borderRadius: BorderRadius.circular(8),
                child: Container(
                  height: 30,
                  padding: const EdgeInsets.symmetric(horizontal: 10),
                  decoration: BoxDecoration(
                    color: AppColors.surfaceLight,
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: AppColors.border),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: const [
                      Icon(Icons.delete_sweep_outlined,
                          size: 15, color: AppColors.textMuted),
                      SizedBox(width: 6),
                      Text('Clear',
                          style: TextStyle(
                              color: AppColors.textMuted, fontSize: 12)),
                    ],
                  ),
                ),
              ),
            ),
            const SizedBox(width: 10),
          ],

          // Live pill
          _LivePill(live: _live, demoMode: demoMode),
        ],
      ),
    );
  }

}

class _PaletteTrigger extends StatelessWidget {
  final VoidCallback onTap;
  final bool open;
  const _PaletteTrigger({required this.onTap, required this.open});

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: 540,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(9),
        child: Container(
          height: 34,
          padding: const EdgeInsets.symmetric(horizontal: 12),
          decoration: BoxDecoration(
            color: AppColors.surfaceLight,
            borderRadius: BorderRadius.circular(9),
            border: Border.all(
                color: open ? AppColors.accent : AppColors.border,
                width: open ? 1.4 : 1),
          ),
          child: Row(
            children: [
              const Icon(Icons.search, size: 16, color: AppColors.textMuted),
              const SizedBox(width: 8),
              const Text('Search alerts, run a command…',
                  style: TextStyle(color: AppColors.textMuted, fontSize: 12)),
              const Spacer(),
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: AppColors.surface,
                  borderRadius: BorderRadius.circular(5),
                  border: Border.all(color: AppColors.border),
                ),
                child: Text('Ctrl K',
                    style: AppText.mono(
                        size: 10, color: AppColors.textMuted)),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _LivePill extends StatelessWidget {
  final bool live;
  final bool demoMode;
  const _LivePill({required this.live, required this.demoMode});

  @override
  Widget build(BuildContext context) {
    final color = live ? AppColors.success : AppColors.textMuted;
    final label = demoMode ? 'DEMO' : (live ? 'LIVE' : 'IDLE');
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 4),
      decoration: BoxDecoration(
        color: color.withOpacity(0.10),
        borderRadius: BorderRadius.circular(20),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 7,
            height: 7,
            decoration: BoxDecoration(color: color, shape: BoxShape.circle),
          ),
          const SizedBox(width: 6),
          Text(label,
              style: AppText.mono(
                  size: 10, weight: FontWeight.w700, color: color)),
        ],
      ),
    );
  }
}
