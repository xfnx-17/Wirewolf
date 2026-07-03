import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import '../ffi/wirewolf_service.dart';
import '../theme/app_theme.dart';

String _actionLabel(int action) => switch (action) {
  1 => '-> LLM',
  2 => 'Cleared',
  _ => 'Filtered',
};

Color _actionColor(int action) => switch (action) {
  1 => AppColors.warning,
  2 => AppColors.success,
  _ => AppColors.textMuted,
};

class ActivityScreen extends StatefulWidget {
  final List<FlowEventData> events;

  const ActivityScreen({super.key, required this.events});

  @override
  State<ActivityScreen> createState() => _ActivityScreenState();
}

class _ActivityScreenState extends State<ActivityScreen> {
  String _filter = '';
  final _scrollController = ScrollController();

  @override
  Widget build(BuildContext context) {
    final timeFmt = DateFormat('HH:mm:ss.SSS');
    final filtered = _filter.isEmpty
        ? widget.events
        : widget.events.where((e) =>
            _actionLabel(e.action).toLowerCase().contains(_filter) ||
            e.reason.toLowerCase().contains(_filter)).toList();

    return Padding(
      padding: const EdgeInsets.all(16),
      child: Card(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Toolbar
            Padding(
              padding: const EdgeInsets.fromLTRB(14, 10, 14, 8),
              child: Row(
                children: [
                  Text('Live Activity  ${widget.events.length} flows',
                      style: const TextStyle(color: AppColors.textSecondary, fontSize: 11, fontWeight: FontWeight.w500)),
                  const Spacer(),
                  SizedBox(
                    width: 180, height: 26,
                    child: TextField(
                      onChanged: (v) => setState(() => _filter = v.toLowerCase()),
                      style: const TextStyle(color: AppColors.textPrimary, fontSize: 10),
                      decoration: InputDecoration(
                        contentPadding: const EdgeInsets.symmetric(horizontal: 8),
                        filled: true, fillColor: AppColors.surfaceLight,
                        hintText: 'Filter...',
                        hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 10),
                        border: OutlineInputBorder(borderRadius: BorderRadius.circular(4), borderSide: BorderSide.none),
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const Divider(height: 1, color: AppColors.border),
            // Header
            Container(
              color: AppColors.surfaceLight,
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
              child: const Row(
                children: [
                  SizedBox(width: 80, child: _H('Time')),
                  SizedBox(width: 140, child: _H('Source')),
                  SizedBox(width: 140, child: _H('Dest')),
                  SizedBox(width: 65, child: _H('Action')),
                  SizedBox(width: 100, child: _H('Reason')),
                  Expanded(child: _H('Size')),
                ],
              ),
            ),
            const Divider(height: 1, color: AppColors.border),
            // Rows
            Expanded(
              child: filtered.isEmpty
                  ? const Center(child: Text('No flow events', style: TextStyle(color: AppColors.textMuted, fontSize: 10)))
                  : ListView.builder(
                      controller: _scrollController,
                      reverse: true,
                      itemCount: filtered.length,
                      itemBuilder: (context, index) {
                        final revIdx = filtered.length - 1 - index;
                        final ev = filtered[revIdx];
                        return Container(
                          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 5),
                          color: index.isOdd ? AppColors.surface : Colors.transparent,
                          child: Row(
                            children: [
                              SizedBox(width: 80, child: Text(timeFmt.format(ev.timestamp), style: const TextStyle(color: AppColors.textMuted, fontSize: 9, fontFamily: 'monospace'))),
                              SizedBox(width: 140, child: Text('${ev.srcIp}:${ev.srcPort}', style: const TextStyle(color: AppColors.textSecondary, fontSize: 9), overflow: TextOverflow.ellipsis)),
                              SizedBox(width: 140, child: Text('${ev.dstIp}:${ev.dstPort}', style: const TextStyle(color: AppColors.textSecondary, fontSize: 9), overflow: TextOverflow.ellipsis)),
                              SizedBox(width: 65, child: Text(_actionLabel(ev.action), style: TextStyle(color: _actionColor(ev.action), fontSize: 9, fontWeight: FontWeight.w600))),
                              SizedBox(width: 100, child: Text(ev.reason, style: const TextStyle(color: AppColors.textSecondary, fontSize: 9))),
                              Expanded(child: Text(ev.payloadSize > 0 ? '${ev.payloadSize}' : '—', style: const TextStyle(color: AppColors.textMuted, fontSize: 9))),
                            ],
                          ),
                        );
                      },
                    ),
            ),
          ],
        ),
      ),
    );
  }

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }
}

class _H extends StatelessWidget {
  final String text;
  const _H(this.text);
  @override
  Widget build(BuildContext context) => Text(text,
      style: const TextStyle(color: AppColors.textMuted, fontSize: 9, fontWeight: FontWeight.w600, letterSpacing: 0.5));
}
