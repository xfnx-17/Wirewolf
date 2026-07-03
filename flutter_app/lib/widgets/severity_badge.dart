import 'package:flutter/material.dart';
import '../theme/app_theme.dart';

class SeverityBadge extends StatelessWidget {
  final String severity;
  final double? cvss;

  const SeverityBadge({
    super.key,
    required this.severity,
    this.cvss,
  });

  @override
  Widget build(BuildContext context) {
    final color = AppColors.severityColorByName(severity);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(3),
      ),
      child: Text(
        cvss != null ? '${severity[0]} ${cvss!.toStringAsFixed(1)}' : severity,
        style: TextStyle(
          color: color,
          fontSize: 11,
          fontWeight: FontWeight.w600,
          fontFamily: 'monospace',
        ),
      ),
    );
  }
}
