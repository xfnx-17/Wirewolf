import 'package:flutter/material.dart';
import '../theme/app_theme.dart';

class PipelineIndicator extends StatelessWidget {
  final String label;
  final int depth;
  final int capacity;
  final int drops;

  const PipelineIndicator({
    super.key,
    required this.label,
    required this.depth,
    required this.capacity,
    required this.drops,
  });

  @override
  Widget build(BuildContext context) {
    final fill = capacity > 0 ? depth / capacity : 0.0;
    final fillColor = fill > 0.8
        ? AppColors.error
        : fill > 0.5
            ? AppColors.warning
            : AppColors.success;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(
              label,
              style: const TextStyle(
                color: AppColors.textSecondary,
                fontSize: 12,
                fontWeight: FontWeight.w500,
              ),
            ),
            Text(
              '$depth / $capacity',
              style: TextStyle(
                color: AppColors.textPrimary,
                fontSize: 12,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
        const SizedBox(height: 6),
        ClipRRect(
          borderRadius: BorderRadius.circular(4),
          child: LinearProgressIndicator(
            value: fill.clamp(0.0, 1.0),
            backgroundColor: AppColors.surfaceLight,
            valueColor: AlwaysStoppedAnimation<Color>(fillColor),
            minHeight: 6,
          ),
        ),
        if (drops > 0) ...[
          const SizedBox(height: 4),
          Text(
            '$drops drops',
            style: const TextStyle(
              color: AppColors.error,
              fontSize: 11,
              fontWeight: FontWeight.w500,
            ),
          ),
        ],
      ],
    );
  }
}
