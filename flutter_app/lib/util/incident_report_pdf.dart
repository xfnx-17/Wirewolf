import 'dart:typed_data';

import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;

import '../ffi/geo_ip.dart';
import '../ffi/wirewolf_service.dart';
import 'incident_report.dart' show explainAlert;

/// Interactive PDF incident report — the Forensic deliverable as a document
/// you can hand to someone. Interactive parts:
///   • sidebar outline (bookmarks) per section and per alert
///   • clickable table of contents + "back to contents" links
///   • external IP links out to AbuseIPDB
///   • fillable AcroForm triage fields per alert (Reviewed / False positive /
///     analyst notes) that persist when saved in any PDF reader
class _Ink {
  static const night = PdfColor.fromInt(0xFF0B0E12);
  static const paper = PdfColor.fromInt(0xFFFFFFFF);
  static const muted = PdfColor.fromInt(0xFF5B6672);
  static const faint = PdfColor.fromInt(0xFFE3E8ED);
  static const amber = PdfColor.fromInt(0xFFFFAD33);
  static const amberDeep = PdfColor.fromInt(0xFF9A5A06);

  static PdfColor severity(String s) => switch (s) {
        'Critical' => const PdfColor.fromInt(0xFFC03434),
        'High' => const PdfColor.fromInt(0xFFD9772E),
        'Medium' => const PdfColor.fromInt(0xFFC29A22),
        'Low' => const PdfColor.fromInt(0xFF3F7FBF),
        _ => const PdfColor.fromInt(0xFF77828D),
      };
}

/// The SIGNAL mark, drawn natively in PDF vector ops (same 72-unit geometry
/// as branding/icon.svg; PDF y-axis points up, so points are flipped).
pw.Widget _mark(double size, PdfColor color) {
  const pts = [
    [4.0, 56.0], [10.0, 56.0], [13.0, 50.0], [16.0, 56.0], [22.0, 56.0],
    [30.0, 26.0], [33.0, 10.0], [38.0, 24.0], [41.0, 24.0], [45.0, 11.0],
    [50.0, 26.0], [55.0, 30.0], [64.0, 38.0], [64.0, 46.0], [58.0, 47.0],
    [46.0, 56.0], [69.0, 56.0],
  ];
  return pw.SizedBox(
    width: size,
    height: size,
    child: pw.CustomPaint(
      size: PdfPoint(size, size),
      painter: (canvas, sz) {
        final f = sz.x / 72.0;
        canvas
          ..setStrokeColor(color)
          ..setLineWidth(4.5 * f)
          ..setLineCap(PdfLineCap.square)
          ..setLineJoin(PdfLineJoin.miter)
          ..moveTo(pts.first[0] * f, (72 - pts.first[1]) * f);
        for (final p in pts.skip(1)) {
          canvas.lineTo(p[0] * f, (72 - p[1]) * f);
        }
        canvas.strokePath();
        // packet-square eye
        canvas
          ..setFillColor(color)
          ..drawRect(48 * f, (72 - 34.5) * f, 4 * f, 4 * f)
          ..fillPath();
      },
    ),
  );
}

pw.Widget _wordmark(double size, PdfColor color) => pw.RichText(
      text: pw.TextSpan(children: [
        pw.TextSpan(
            text: 'WIRE',
            style: pw.TextStyle(
                fontSize: size,
                color: color,
                fontWeight: pw.FontWeight.normal,
                letterSpacing: size * 0.12)),
        pw.TextSpan(
            text: 'WOLF',
            style: pw.TextStyle(
                fontSize: size,
                color: color,
                fontWeight: pw.FontWeight.bold,
                letterSpacing: size * 0.12)),
      ]),
    );

pw.Widget _sevChip(String severity, {String? label}) => pw.Container(
      padding: const pw.EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: pw.BoxDecoration(
        color: _Ink.severity(severity),
        borderRadius: pw.BorderRadius.circular(3),
      ),
      child: pw.Text(label ?? severity.toUpperCase(),
          style: pw.TextStyle(
              color: _Ink.paper,
              fontSize: 7.5,
              fontWeight: pw.FontWeight.bold,
              letterSpacing: 0.8)),
    );

String _hms(DateTime t) => t.toIso8601String().substring(11, 19);

/// The built-in Type1 PDF fonts only cover Latin-1; explainAlert prose uses
/// em dashes and payload snippets can carry arbitrary bytes. Map the common
/// typographic characters down and replace anything else non-Latin-1 with '?'.
String _pdfSafe(String s) {
  final swapped = s
      .replaceAll('—', '-')
      .replaceAll('–', '-')
      .replaceAll('…', '...')
      .replaceAll('‘', "'")
      .replaceAll('’', "'")
      .replaceAll('“', '"')
      .replaceAll('”', '"');
  return String.fromCharCodes(
      swapped.runes.map((r) => r < 256 ? r : 0x3F /* ? */));
}

Future<Uint8List> buildIncidentReportPdf(List<AlertData> alerts) async {
  final doc = pw.Document(
    title: 'Wirewolf Incident Report',
    creator: 'Wirewolf',
  );
  final mono = pw.Font.courier();
  final now = DateTime.now();
  final sorted = [...alerts]..sort((a, b) => a.timestamp.compareTo(b.timestamp));

  final bySev = <String, int>{};
  final atk = <String, int>{};
  final tgt = <String, int>{};
  for (final a in alerts) {
    bySev[a.severity] = (bySev[a.severity] ?? 0) + 1;
    atk[a.srcIp] = (atk[a.srcIp] ?? 0) + 1;
    tgt[a.dstIp] = (tgt[a.dstIp] ?? 0) + 1;
  }
  List<MapEntry<String, int>> top(Map<String, int> m) =>
      (m.entries.toList()..sort((x, y) => y.value.compareTo(x.value)))
          .take(5)
          .toList();

  // ---------- cover ----------
  doc.addPage(pw.Page(
    pageFormat: PdfPageFormat.a4,
    margin: pw.EdgeInsets.zero,
    build: (ctx) => pw.Container(
      width: double.infinity,
      height: double.infinity,
      color: _Ink.night,
      padding: const pw.EdgeInsets.fromLTRB(56, 64, 56, 48),
      child: pw.Column(
        crossAxisAlignment: pw.CrossAxisAlignment.start,
        children: [
          _mark(110, _Ink.amber),
          pw.SizedBox(height: 22),
          _wordmark(38, PdfColor.fromInt(0xFFE9EEF3)),
          pw.SizedBox(height: 8),
          pw.Text('INCIDENT REPORT',
              style: pw.TextStyle(
                  font: mono,
                  fontSize: 12,
                  color: _Ink.amber,
                  letterSpacing: 4)),
          pw.SizedBox(height: 40),
          pw.Text(
              sorted.isEmpty
                  ? 'No alerts in session'
                  : 'Capture window  ${sorted.first.timestamp.toIso8601String().substring(0, 19)}  to  ${sorted.last.timestamp.toIso8601String().substring(0, 19)}',
              style: pw.TextStyle(
                  font: mono, fontSize: 9, color: PdfColor.fromInt(0xFF8A96A3))),
          pw.SizedBox(height: 18),
          pw.Text('${alerts.length}',
              style: pw.TextStyle(
                  fontSize: 54,
                  fontWeight: pw.FontWeight.bold,
                  color: PdfColor.fromInt(0xFFE9EEF3))),
          pw.Text('alerts',
              style: const pw.TextStyle(
                  fontSize: 12, color: PdfColor.fromInt(0xFF8A96A3))),
          pw.SizedBox(height: 16),
          pw.Wrap(spacing: 6, runSpacing: 6, children: [
            for (final s in ['Critical', 'High', 'Medium', 'Low', 'Info'])
              if (bySev[s] != null) _sevChip(s, label: '$s ${bySev[s]}'.toUpperCase()),
          ]),
          pw.Spacer(),
          pw.Container(height: 2, width: 120, color: _Ink.amber),
          pw.SizedBox(height: 10),
          pw.Text('Generated ${now.toIso8601String().substring(0, 19)}  ·  Wirewolf forensic engine',
              style: pw.TextStyle(
                  font: mono, fontSize: 8, color: PdfColor.fromInt(0xFF8A96A3))),
        ],
      ),
    ),
  ));

  if (alerts.isEmpty) return doc.save();

  // ---------- body ----------
  final headerStyle = pw.TextStyle(
      font: mono, fontSize: 8, color: _Ink.muted, letterSpacing: 1.5);

  doc.addPage(pw.MultiPage(
    pageFormat: PdfPageFormat.a4,
    margin: const pw.EdgeInsets.fromLTRB(48, 52, 48, 56),
    header: (ctx) => pw.Container(
      margin: const pw.EdgeInsets.only(bottom: 18),
      padding: const pw.EdgeInsets.only(bottom: 8),
      decoration: const pw.BoxDecoration(
          border: pw.Border(bottom: pw.BorderSide(color: _Ink.faint, width: 0.7))),
      child: pw.Row(children: [
        _mark(14, _Ink.amberDeep),
        pw.SizedBox(width: 8),
        pw.Text('WIREWOLF · INCIDENT REPORT', style: headerStyle),
        pw.Spacer(),
        pw.Text(now.toIso8601String().substring(0, 10), style: headerStyle),
      ]),
    ),
    footer: (ctx) => pw.Container(
      margin: const pw.EdgeInsets.only(top: 14),
      child: pw.Row(children: [
        pw.Text('Triage fields in this document are fillable and save with the file.',
            style: pw.TextStyle(font: mono, fontSize: 7, color: _Ink.muted)),
        pw.Spacer(),
        pw.Text('${ctx.pageNumber} / ${ctx.pagesCount}',
            style: pw.TextStyle(font: mono, fontSize: 8, color: _Ink.muted)),
      ]),
    ),
    build: (ctx) => [
      // ---- key hosts ----
      pw.Outline(name: 'sum', title: 'Summary', level: 0),
      pw.Text('Key hosts',
          style: pw.TextStyle(fontSize: 16, fontWeight: pw.FontWeight.bold)),
      pw.SizedBox(height: 10),
      pw.Row(crossAxisAlignment: pw.CrossAxisAlignment.start, children: [
        for (final (title, entries) in [('Top sources', top(atk)), ('Top targets', top(tgt))])
          pw.Expanded(
            child: pw.Container(
              margin: const pw.EdgeInsets.only(right: 10),
              padding: const pw.EdgeInsets.all(10),
              decoration: pw.BoxDecoration(
                  border: pw.Border.all(color: _Ink.faint, width: 0.7),
                  borderRadius: pw.BorderRadius.circular(4)),
              child: pw.Column(
                crossAxisAlignment: pw.CrossAxisAlignment.start,
                children: [
                  pw.Text(title.toUpperCase(),
                      style: pw.TextStyle(
                          font: mono, fontSize: 7.5,
                          color: _Ink.amberDeep, letterSpacing: 1.2)),
                  pw.SizedBox(height: 6),
                  for (final e in entries)
                    pw.Padding(
                      padding: const pw.EdgeInsets.only(bottom: 2),
                      child: pw.Row(children: [
                        pw.Expanded(
                            child: pw.Text(e.key,
                                style: pw.TextStyle(font: mono, fontSize: 9))),
                        pw.Text('${e.value}',
                            style: pw.TextStyle(
                                font: mono, fontSize: 9, color: _Ink.muted)),
                      ]),
                    ),
                ],
              ),
            ),
          ),
      ]),
      pw.SizedBox(height: 24),

      // ---- clickable contents ----
      pw.Anchor(name: 'toc', child: pw.SizedBox()),
      pw.Outline(name: 'toc_o', title: 'Contents', level: 0),
      pw.Text('Contents',
          style: pw.TextStyle(fontSize: 16, fontWeight: pw.FontWeight.bold)),
      pw.SizedBox(height: 4),
      pw.Text('Every row is clickable; the sidebar bookmarks mirror this list.',
          style: const pw.TextStyle(fontSize: 9, color: _Ink.muted)),
      pw.SizedBox(height: 10),
      for (var i = 0; i < sorted.length; i++)
        pw.Link(
          destination: 'alert_$i',
          child: pw.Container(
            padding: const pw.EdgeInsets.symmetric(vertical: 4, horizontal: 6),
            decoration: pw.BoxDecoration(
                border: pw.Border(
                    bottom: pw.BorderSide(color: _Ink.faint, width: 0.5))),
            child: pw.Row(children: [
              pw.SizedBox(
                  width: 24,
                  child: pw.Text('${i + 1}',
                      style: pw.TextStyle(
                          font: mono, fontSize: 9, color: _Ink.muted))),
              pw.SizedBox(
                  width: 54,
                  child: pw.Text(_hms(sorted[i].timestamp),
                      style: pw.TextStyle(font: mono, fontSize: 9))),
              pw.Expanded(
                  child: pw.Text(sorted[i].threatType,
                      style: pw.TextStyle(
                          fontSize: 10, fontWeight: pw.FontWeight.bold))),
              pw.Text('${sorted[i].srcIp} » ${sorted[i].dstIp}',
                  style: pw.TextStyle(
                      font: mono, fontSize: 8, color: _Ink.muted)),
              pw.SizedBox(width: 8),
              _sevChip(sorted[i].severity),
            ]),
          ),
        ),
      pw.SizedBox(height: 24),

      // ---- alert sections ----
      pw.Outline(name: 'alerts_o', title: 'Alerts', level: 0),
      for (var i = 0; i < sorted.length; i++) ..._alertSection(i, sorted[i], mono),
    ],
  ));

  return doc.save();
}

List<pw.Widget> _alertSection(int i, AlertData a, pw.Font mono) {
  final ext = externalEndpoint(a.srcIp, a.dstIp);
  final snippet = _pdfSafe(a.snippet.trim());
  // Sections are emitted as sibling widgets (band, body) rather than one big
  // bordered container: bordered containers span page breaks as a stretched
  // empty frame, while siblings flow naturally.
  return [
    // header band with severity stripe
    pw.Container(
      decoration: pw.BoxDecoration(
        color: const PdfColor.fromInt(0xFFF4F6F8),
        border: pw.Border(
            left: pw.BorderSide(color: _Ink.severity(a.severity), width: 3)),
      ),
      padding: const pw.EdgeInsets.symmetric(horizontal: 10, vertical: 7),
      child: pw.Row(children: [
        pw.Anchor(
          name: 'alert_$i',
          child: pw.Outline(
            name: 'alert_o_$i',
            title: '${i + 1}. ${a.threatType} (${a.severity})',
            level: 1,
            child: pw.Text('${i + 1}.  ${a.threatType}',
                style: pw.TextStyle(
                    fontSize: 12, fontWeight: pw.FontWeight.bold)),
          ),
        ),
        pw.Spacer(),
        _sevChip(a.severity,
            label:
                '${a.severity} · CVSS ${a.cvss.toStringAsFixed(1)}'.toUpperCase()),
      ]),
    ),
    pw.Container(
      margin: const pw.EdgeInsets.only(bottom: 18),
      padding: const pw.EdgeInsets.fromLTRB(13, 10, 4, 0),
      decoration: const pw.BoxDecoration(
          border: pw.Border(
              left: pw.BorderSide(color: _Ink.faint, width: 3))),
      child: pw.Column(crossAxisAlignment: pw.CrossAxisAlignment.start, children: [
            // meta grid
            pw.Row(children: [
              for (final (k, v) in [
                ('TIME', _hms(a.timestamp)),
                ('SOURCE', '${a.srcIp}:${a.srcPort}'),
                ('TARGET', '${a.dstIp}:${a.dstPort}'),
                ('CONFIDENCE', '${a.confidencePct}%'),
              ])
                pw.Expanded(
                  child: pw.Column(
                    crossAxisAlignment: pw.CrossAxisAlignment.start,
                    children: [
                      pw.Text(k,
                          style: pw.TextStyle(
                              font: mono, fontSize: 6.5,
                              color: _Ink.muted, letterSpacing: 1)),
                      pw.SizedBox(height: 2),
                      pw.Text(v, style: pw.TextStyle(font: mono, fontSize: 9)),
                    ],
                  ),
                ),
            ]),
            pw.SizedBox(height: 8),
            pw.Text(_pdfSafe(explainAlert(a)),
                style: const pw.TextStyle(fontSize: 9.5, lineSpacing: 2)),
            if (snippet.isNotEmpty) ...[
              pw.SizedBox(height: 8),
              pw.Container(
                width: double.infinity,
                padding: const pw.EdgeInsets.all(8),
                decoration: pw.BoxDecoration(
                    color: _Ink.night, borderRadius: pw.BorderRadius.circular(3)),
                child: pw.Text(
                    snippet.length > 500 ? '${snippet.substring(0, 500)}...' : snippet,
                    style: pw.TextStyle(
                        font: mono, fontSize: 7.5,
                        color: const PdfColor.fromInt(0xFFE9EEF3))),
              ),
            ],
            if (ext != null) ...[
              pw.SizedBox(height: 8),
              pw.UrlLink(
                destination: 'https://www.abuseipdb.com/check/${ext.ip}',
                child: pw.Text('Check ${ext.ip} on AbuseIPDB »',
                    style: pw.TextStyle(
                        fontSize: 8.5,
                        color: _Ink.amberDeep,
                        decoration: pw.TextDecoration.underline)),
              ),
            ],
            pw.SizedBox(height: 10),
            // fillable triage row
            pw.Container(
              padding: const pw.EdgeInsets.only(top: 8),
              decoration: const pw.BoxDecoration(
                  border: pw.Border(
                      top: pw.BorderSide(color: _Ink.faint, width: 0.5))),
              child: pw.Row(crossAxisAlignment: pw.CrossAxisAlignment.center, children: [
                pw.Checkbox(name: 'reviewed_$i', value: false,
                    width: 10, height: 10, activeColor: _Ink.amberDeep),
                pw.SizedBox(width: 4),
                pw.Text('Reviewed', style: const pw.TextStyle(fontSize: 8.5)),
                pw.SizedBox(width: 14),
                pw.Checkbox(name: 'falsepos_$i', value: false,
                    width: 10, height: 10, activeColor: _Ink.amberDeep),
                pw.SizedBox(width: 4),
                pw.Text('False positive', style: const pw.TextStyle(fontSize: 8.5)),
                pw.SizedBox(width: 14),
                pw.Text('NOTES',
                    style: pw.TextStyle(
                        font: mono, fontSize: 6.5,
                        color: _Ink.muted, letterSpacing: 1)),
                pw.SizedBox(width: 6),
                pw.Expanded(
                  child: pw.Container(
                    decoration: const pw.BoxDecoration(
                        border: pw.Border(
                            bottom: pw.BorderSide(
                                color: _Ink.muted, width: 0.6))),
                    child: pw.TextField(
                      name: 'notes_$i',
                      height: 16,
                      textStyle: pw.TextStyle(font: mono, fontSize: 8),
                    ),
                  ),
                ),
              ]),
            ),
            pw.SizedBox(height: 6),
            pw.Link(
                destination: 'toc',
                child: pw.Text('» Back to contents',
                    style: const pw.TextStyle(fontSize: 7.5, color: _Ink.muted))),
      ]),
    ),
  ];
}
