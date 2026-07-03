import 'package:flutter/material.dart';

/// The Wirewolf SIGNAL mark — one continuous packet trace that spikes into
/// a wolf head. Geometry mirrors branding/favicon.svg (bold small-size cut)
/// and branding/icon.svg (full cut with blip + eye), both on a 72-unit box.
class WirewolfMark extends StatelessWidget {
  final double size;
  final Color color;

  /// Bold favicon cut for small sizes; full cut (blip + eye) above 40px.
  final bool? bold;

  const WirewolfMark({
    super.key,
    this.size = 16,
    this.color = const Color(0xFFFFAD33),
    this.bold,
  });

  @override
  Widget build(BuildContext context) {
    return CustomPaint(
      size: Size.square(size),
      painter: _MarkPainter(color, bold ?? size < 40),
    );
  }
}

class _MarkPainter extends CustomPainter {
  final Color color;
  final bool bold;
  _MarkPainter(this.color, this.bold);

  static const _fav = [
    Offset(5, 56), Offset(20, 56), Offset(30, 26), Offset(33, 10),
    Offset(38, 24), Offset(41, 24), Offset(45, 11), Offset(50, 26),
    Offset(55, 30), Offset(64, 38), Offset(64, 46), Offset(58, 47),
    Offset(46, 56), Offset(67, 56),
  ];
  static const _full = [
    Offset(4, 56), Offset(10, 56), Offset(13, 50), Offset(16, 56),
    Offset(22, 56), Offset(30, 26), Offset(33, 10), Offset(38, 24),
    Offset(41, 24), Offset(45, 11), Offset(50, 26), Offset(55, 30),
    Offset(64, 38), Offset(64, 46), Offset(58, 47), Offset(46, 56),
    Offset(69, 56),
  ];

  @override
  void paint(Canvas canvas, Size size) {
    final f = size.shortestSide / 72.0;
    final pts = bold ? _fav : _full;
    final path = Path()..moveTo(pts.first.dx * f, pts.first.dy * f);
    for (final p in pts.skip(1)) {
      path.lineTo(p.dx * f, p.dy * f);
    }
    final paint = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = (bold ? 6.5 : 4.5) * f
      ..strokeCap = StrokeCap.square
      ..strokeJoin = StrokeJoin.miter
      ..strokeMiterLimit = bold ? 2.5 : 4.0
      ..color = color;
    canvas.drawPath(path, paint);
    if (!bold) {
      canvas.drawRect(
          Rect.fromLTWH(48 * f, 30.5 * f, 4 * f, 4 * f), Paint()..color = color);
    }
  }

  @override
  bool shouldRepaint(covariant _MarkPainter old) =>
      old.color != color || old.bold != bold;
}
