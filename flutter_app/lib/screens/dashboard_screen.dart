import 'package:flutter/material.dart';
import '../ffi/wirewolf_service.dart';
import '../theme/app_theme.dart';
import '../widgets/severity_stat_card.dart';
import '../panels/alerts_timeline_chart.dart';
import '../panels/threat_distribution_chart.dart';
import '../panels/severity_donut_chart.dart';
import '../panels/filter_funnel_chart.dart';
import '../panels/top_sources_chart.dart';
import '../panels/top_targets_chart.dart';
import '../panels/alerts_table.dart';

class DashboardScreen extends StatelessWidget {
  final WirewolfService? service;
  final List<AlertData> alerts;
  final StatsData? stats;
  final PipelineState pipelineState;
  final bool demoMode;
  final int? selectedAlertIndex;
  final ValueChanged<int?> onSelectAlert;

  const DashboardScreen({
    super.key,
    this.service,
    required this.alerts,
    required this.stats,
    required this.pipelineState,
    this.demoMode = false,
    required this.selectedAlertIndex,
    required this.onSelectAlert,
  });

  int _countBySeverity(int level) =>
      alerts.where((a) => a.severityLevel == level).length;

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        children: [
          _buildSeverityRow(),
          const SizedBox(height: 12),
          _buildRow2(),
          const SizedBox(height: 12),
          _buildRow3(),
          const SizedBox(height: 12),
          SizedBox(
            height: 400,
            child: AlertsTable(
              alerts: alerts,
              selectedIndex: selectedAlertIndex,
              onSelect: onSelectAlert,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSeverityRow() {
    return IntrinsicHeight(
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Expanded(child: SeverityStatCard(label: 'Critical', count: _countBySeverity(4), color: AppColors.critical)),
          const SizedBox(width: 8),
          Expanded(child: SeverityStatCard(label: 'High', count: _countBySeverity(3), color: AppColors.high)),
          const SizedBox(width: 8),
          Expanded(child: SeverityStatCard(label: 'Medium', count: _countBySeverity(2), color: AppColors.medium)),
          const SizedBox(width: 8),
          Expanded(child: SeverityStatCard(label: 'Low', count: _countBySeverity(1), color: AppColors.low)),
          const SizedBox(width: 8),
          Expanded(
            flex: 2,
            child: Card(
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                child: Row(
                  children: [
                    _summaryItem('Total', '${alerts.length}', AppColors.textPrimary),
                    Container(width: 1, height: 28, color: AppColors.border),
                    _summaryItem('Flows', _fmt(stats?.totalFlows ?? 0), AppColors.accent),
                    Container(width: 1, height: 28, color: AppColors.border),
                    _summaryItem('Filtered', _fmt(stats?.filterDropped ?? 0), AppColors.success),
                    Container(width: 1, height: 28, color: AppColors.border),
                    _summaryItem('Deduped', '${stats?.filterDeduped ?? 0}', AppColors.textSecondary),
                    if ((stats?.blockedPackets ?? 0) > 0 ||
                        (stats?.blockedSources ?? 0) > 0) ...[
                      Container(width: 1, height: 28, color: AppColors.border),
                      _summaryItem(
                        'Blocked',
                        '${_fmt(stats?.blockedPackets ?? 0)} / ${stats?.blockedSources ?? 0} src',
                        AppColors.error),
                    ],
                  ],
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildRow2() {
    return SizedBox(
      height: 220,
      child: Row(
        children: [
          Expanded(flex: 4, child: AlertsTimelineChart(alerts: alerts)),
          const SizedBox(width: 8),
          Expanded(flex: 2, child: SeverityDonutChart(alerts: alerts)),
          const SizedBox(width: 8),
          Expanded(flex: 2, child: FilterFunnelChart(stats: stats)),
        ],
      ),
    );
  }

  Widget _buildRow3() {
    return SizedBox(
      height: 200,
      child: Row(
        children: [
          Expanded(flex: 3, child: ThreatDistributionChart(alerts: alerts)),
          const SizedBox(width: 8),
          Expanded(
              flex: 2,
              child: TopSourcesChart(
                alerts: alerts,
                selectedAlertIndex: selectedAlertIndex,
                onSelect: onSelectAlert,
              )),
          const SizedBox(width: 8),
          Expanded(
              flex: 2,
              child: TopTargetsChart(
                alerts: alerts,
                selectedAlertIndex: selectedAlertIndex,
                onSelect: onSelectAlert,
              )),
        ],
      ),
    );
  }

  Widget _summaryItem(String label, String value, Color color) {
    return Expanded(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Text(label, style: const TextStyle(color: AppColors.textMuted, fontSize: 9)),
          const SizedBox(height: 2),
          Text(value, style: TextStyle(color: color, fontSize: 16, fontWeight: FontWeight.w600)),
        ],
      ),
    );
  }

  String _fmt(int n) {
    if (n >= 1000000) return '${(n / 1000000).toStringAsFixed(1)}M';
    if (n >= 1000) return '${(n / 1000).toStringAsFixed(1)}K';
    return n.toString();
  }
}
