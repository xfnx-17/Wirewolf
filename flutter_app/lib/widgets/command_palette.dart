import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../theme/app_theme.dart';

class PaletteCommand {
  final String label;
  final String shortcut;
  final IconData icon;
  final VoidCallback onRun;
  const PaletteCommand(this.label, this.shortcut, this.icon, this.onRun);
}

/// Centered command-palette overlay. Renders a dim scrim, a search field that
/// filters the command list, and keyboard navigation (arrows + enter + esc).
class CommandPalette extends StatefulWidget {
  final List<PaletteCommand> commands;
  final VoidCallback onClose;

  const CommandPalette({
    super.key,
    required this.commands,
    required this.onClose,
  });

  @override
  State<CommandPalette> createState() => _CommandPaletteState();
}

class _CommandPaletteState extends State<CommandPalette> {
  final _controller = TextEditingController();
  final _focus = FocusNode();
  String _query = '';
  int _highlight = 0;

  List<PaletteCommand> get _filtered {
    if (_query.isEmpty) return widget.commands;
    final q = _query.toLowerCase();
    return widget.commands
        .where((c) =>
            c.label.toLowerCase().contains(q) ||
            c.shortcut.toLowerCase().contains(q))
        .toList();
  }

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _focus.requestFocus());
  }

  void _run(PaletteCommand c) {
    widget.onClose();
    c.onRun();
  }

  @override
  Widget build(BuildContext context) {
    final filtered = _filtered;
    final highlight = _highlight.clamp(0, filtered.isEmpty ? 0 : filtered.length - 1);

    return Positioned.fill(
      child: GestureDetector(
        onTap: widget.onClose,
        child: Container(
          color: Colors.black.withOpacity(0.18),
          alignment: Alignment.topCenter,
          padding: const EdgeInsets.only(top: 96),
          child: GestureDetector(
            onTap: () {},
            child: CallbackShortcuts(
              bindings: {
                const SingleActivator(LogicalKeyboardKey.escape):
                    widget.onClose,
                const SingleActivator(LogicalKeyboardKey.arrowDown): () {
                  if (filtered.isEmpty) return;
                  setState(() =>
                      _highlight = (highlight + 1) % filtered.length);
                },
                const SingleActivator(LogicalKeyboardKey.arrowUp): () {
                  if (filtered.isEmpty) return;
                  setState(() => _highlight =
                      (highlight - 1 + filtered.length) % filtered.length);
                },
                const SingleActivator(LogicalKeyboardKey.enter): () {
                  if (filtered.isNotEmpty) _run(filtered[highlight]);
                },
              },
              child: Container(
              width: 560,
              decoration: BoxDecoration(
                color: AppColors.surface,
                borderRadius: BorderRadius.circular(14),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withOpacity(0.18),
                    blurRadius: 40,
                    offset: const Offset(0, 16),
                  ),
                ],
              ),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  // Search field
                  Padding(
                    padding: const EdgeInsets.fromLTRB(14, 12, 14, 10),
                    child: Row(
                      children: [
                        const Icon(Icons.search,
                            size: 18, color: AppColors.textMuted),
                        const SizedBox(width: 10),
                        Expanded(
                          child: TextField(
                            controller: _controller,
                            focusNode: _focus,
                            style: const TextStyle(
                                color: AppColors.textPrimary, fontSize: 14),
                            decoration: const InputDecoration(
                              isDense: true,
                              border: InputBorder.none,
                              hintText: 'Search alerts, run a command…',
                              hintStyle: TextStyle(
                                  color: AppColors.textMuted, fontSize: 14),
                            ),
                            onChanged: (v) => setState(() {
                              _query = v;
                              _highlight = 0;
                            }),
                          ),
                        ),
                      ],
                    ),
                  ),
                  const Divider(height: 1, color: AppColors.border),
                  // Command list
                  ConstrainedBox(
                    constraints: const BoxConstraints(maxHeight: 320),
                    child: ListView.builder(
                      shrinkWrap: true,
                      padding: const EdgeInsets.all(6),
                      itemCount: filtered.length,
                      itemBuilder: (context, i) {
                        final c = filtered[i];
                        final active = i == highlight;
                        return InkWell(
                          onTap: () => _run(c),
                          onHover: (h) {
                            if (h) setState(() => _highlight = i);
                          },
                          borderRadius: BorderRadius.circular(9),
                          child: Container(
                            padding: const EdgeInsets.symmetric(
                                horizontal: 10, vertical: 10),
                            decoration: BoxDecoration(
                              color: active
                                  ? AppColors.accent.withOpacity(0.08)
                                  : Colors.transparent,
                              borderRadius: BorderRadius.circular(9),
                            ),
                            child: Row(
                              children: [
                                Icon(c.icon,
                                    size: 17,
                                    color: active
                                        ? AppColors.accent
                                        : AppColors.textMuted),
                                const SizedBox(width: 12),
                                Text(c.label,
                                    style: const TextStyle(
                                        color: AppColors.textPrimary,
                                        fontSize: 13,
                                        fontWeight: FontWeight.w500)),
                                const Spacer(),
                                Text(c.shortcut,
                                    style: AppText.mono(
                                        size: 11, color: AppColors.textMuted)),
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
            ),
          ),
        ),
      ),
    );
  }

  @override
  void dispose() {
    _controller.dispose();
    _focus.dispose();
    super.dispose();
  }
}
