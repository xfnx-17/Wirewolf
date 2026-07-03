import 'package:flutter/material.dart';
import '../ffi/wirewolf_service.dart';
import '../theme/app_theme.dart';

String _levelName(int level) => switch (level) { 0 => 'DEBUG', 1 => 'INFO', 2 => 'WARN', 3 => 'ERROR', _ => '?' };
Color _levelColor(int level) => switch (level) { 0 => AppColors.textMuted, 1 => AppColors.textSecondary, 2 => AppColors.warning, 3 => AppColors.error, _ => AppColors.textPrimary };

class LogScreen extends StatefulWidget {
  final List<LogEntryData> entries;

  const LogScreen({super.key, required this.entries});

  @override
  State<LogScreen> createState() => _LogScreenState();
}

class _LogScreenState extends State<LogScreen> {
  int _minLevel = 0;
  String _filter = '';
  final _scrollController = ScrollController();

  @override
  Widget build(BuildContext context) {
    final filtered = widget.entries.where((e) {
      if (e.level < _minLevel) return false;
      if (_filter.isNotEmpty && !e.message.toLowerCase().contains(_filter) && !e.component.toLowerCase().contains(_filter)) return false;
      return true;
    }).toList();

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
                  Text('Log  ${filtered.length} lines',
                      style: const TextStyle(color: AppColors.textSecondary, fontSize: 11, fontWeight: FontWeight.w500)),
                  const SizedBox(width: 16),
                  // Level filter
                  ...['ALL', 'INFO+', 'WARN+', 'ERR'].asMap().entries.map((e) {
                    final selected = _minLevel == e.key;
                    return Padding(
                      padding: const EdgeInsets.only(right: 4),
                      child: InkWell(
                        onTap: () => setState(() => _minLevel = e.key),
                        borderRadius: BorderRadius.circular(3),
                        child: Container(
                          padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                          decoration: BoxDecoration(
                            color: selected ? AppColors.accent.withOpacity(0.15) : Colors.transparent,
                            borderRadius: BorderRadius.circular(3),
                          ),
                          child: Text(e.value,
                              style: TextStyle(color: selected ? AppColors.accent : AppColors.textMuted, fontSize: 9, fontWeight: FontWeight.w600)),
                        ),
                      ),
                    );
                  }),
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
            // Log lines
            Expanded(
              child: filtered.isEmpty
                  ? const Center(child: Text('No log entries', style: TextStyle(color: AppColors.textMuted, fontSize: 10)))
                  : ListView.builder(
                      controller: _scrollController,
                      reverse: true,
                      itemCount: filtered.length,
                      itemBuilder: (context, index) {
                        final revIdx = filtered.length - 1 - index;
                        final entry = filtered[revIdx];
                        return Padding(
                          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 1),
                          child: RichText(
                            text: TextSpan(
                              style: const TextStyle(fontSize: 10, fontFamily: 'monospace', height: 1.6),
                              children: [
                                TextSpan(text: '[${_levelName(entry.level)}] ', style: TextStyle(color: _levelColor(entry.level), fontWeight: FontWeight.w600)),
                                TextSpan(text: '[${entry.component}] ', style: const TextStyle(color: AppColors.textMuted)),
                                TextSpan(text: entry.message, style: TextStyle(color: _levelColor(entry.level))),
                              ],
                            ),
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
