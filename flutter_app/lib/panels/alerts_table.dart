import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import '../ffi/wirewolf_service.dart';
import '../theme/app_theme.dart';
import '../widgets/severity_badge.dart';

class AlertsTable extends StatelessWidget {
  final List<AlertData> alerts;
  final int? selectedIndex;
  final ValueChanged<int?> onSelect;

  const AlertsTable({
    super.key,
    required this.alerts,
    required this.selectedIndex,
    required this.onSelect,
  });

  @override
  Widget build(BuildContext context) {
    final timeFmt = DateFormat('HH:mm:ss');

    return Card(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(14, 10, 14, 8),
            child: Text(
              'Threat Alerts  ${alerts.length}',
              style: const TextStyle(color: AppColors.textSecondary, fontSize: 11, fontWeight: FontWeight.w500),
            ),
          ),
          const Divider(height: 1, color: AppColors.border),
          // Header row
          Container(
            color: AppColors.surfaceLight,
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
            child: const Row(
              children: [
                SizedBox(width: 70, child: _HeaderText('Time')),
                SizedBox(width: 150, child: _HeaderText('Source')),
                SizedBox(width: 150, child: _HeaderText('Dest')),
                SizedBox(width: 160, child: _HeaderText('Type')),
                SizedBox(width: 160, child: _HeaderText('Severity')),
                SizedBox(width: 12),
                Expanded(child: _HeaderText('Snippet')),
              ],
            ),
          ),
          const Divider(height: 1, color: AppColors.border),
          // Data rows
          Expanded(
            child: alerts.isEmpty
                ? const Center(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(Icons.shield_outlined,
                            size: 48, color: AppColors.textMuted),
                        SizedBox(height: 12),
                        Text(
                          'No threats detected',
                          style: TextStyle(color: AppColors.textMuted),
                        ),
                      ],
                    ),
                  )
                : ListView.builder(
                    itemCount: alerts.length,
                    reverse: true,
                    itemBuilder: (context, index) {
                      // Show newest first
                      final revIndex = alerts.length - 1 - index;
                      final alert = alerts[revIndex];
                      final isSelected = selectedIndex == revIndex;

                      return InkWell(
                        onTap: () => onSelect(isSelected ? null : revIndex),
                        child: Container(
                          color: isSelected
                              ? AppColors.accent.withOpacity(0.08)
                              : (index.isOdd
                                  ? AppColors.surface
                                  : Colors.transparent),
                          padding: const EdgeInsets.symmetric(
                              horizontal: 16, vertical: 10),
                          child: Row(
                            children: [
                              SizedBox(
                                width: 70,
                                child: Text(
                                  timeFmt.format(alert.timestamp),
                                  style: const TextStyle(
                                    color: AppColors.textMuted,
                                    fontSize: 10,
                                    fontFamily: 'monospace',
                                  ),
                                ),
                              ),
                              SizedBox(
                                width: 150,
                                child: Text(
                                  '${alert.srcIp}:${alert.srcPort}',
                                  style: const TextStyle(
                                    color: AppColors.textSecondary,
                                    fontSize: 10,
                                  ),
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                              SizedBox(
                                width: 150,
                                child: Text(
                                  '${alert.dstIp}:${alert.dstPort}',
                                  style: const TextStyle(
                                    color: AppColors.textSecondary,
                                    fontSize: 10,
                                  ),
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                              SizedBox(
                                width: 160,
                                child: Text(
                                  alert.threatType,
                                  style: const TextStyle(
                                    color: AppColors.textPrimary,
                                    fontSize: 10,
                                    fontWeight: FontWeight.w500,
                                  ),
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                              SizedBox(
                                width: 160,
                                child: Align(
                                  alignment: Alignment.centerLeft,
                                  child: SeverityBadge(
                                    severity: alert.severityLabel,
                                    cvss: alert.cvss,
                                  ),
                                ),
                              ),
                              const SizedBox(width: 12),
                              Expanded(
                                child: Text(
                                  alert.snippet,
                                  style: const TextStyle(
                                    color: AppColors.textSecondary,
                                    fontSize: 10,
                                    fontFamily: 'monospace',
                                  ),
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                            ],
                          ),
                        ),
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }
}

class _HeaderText extends StatelessWidget {
  final String text;
  const _HeaderText(this.text);

  @override
  Widget build(BuildContext context) {
    return Text(
      text,
      style: const TextStyle(
        color: AppColors.textMuted,
        fontSize: 11,
        fontWeight: FontWeight.w600,
        letterSpacing: 0.5,
      ),
    );
  }
}
