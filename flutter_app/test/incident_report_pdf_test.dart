import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:wirewolf_dashboard/ffi/wirewolf_service.dart';
import 'package:wirewolf_dashboard/util/incident_report_pdf.dart';

void main() {
  test('interactive PDF incident report builds from alerts', () async {
    final alerts = [
      AlertData(
        srcIp: '203.0.113.66', srcPort: 51544,
        dstIp: '192.168.1.20', dstPort: 443,
        threatType: 'C2 Beaconing', severity: 'Critical',
        cvss: 9.1, severityLevel: 4,
        snippet: 'POST /gate.php HTTP/1.1  Host: update-cdn.example',
        rawLlmOutput: '{"threat_type":"C2 Beaconing"}',
        payloadText: 'beacon payload',
        timestamp: DateTime(2026, 7, 3, 12, 30, 5),
        confidence: 0.93,
      ),
      AlertData(
        srcIp: '192.168.1.7', srcPort: 40112,
        dstIp: '198.51.100.9', dstPort: 80,
        threatType: 'SQLi', severity: 'High',
        cvss: 8.2, severityLevel: 3,
        snippet: "id=1' OR '1'='1",
        rawLlmOutput: '{"threat_type":"SQLi"}',
        payloadText: 'GET /users?id=1',
        timestamp: DateTime(2026, 7, 3, 12, 31, 44),
        confidence: 0.88,
      ),
    ];

    final bytes = await buildIncidentReportPdf(alerts);
    expect(bytes.length, greaterThan(8000));

    // Empty alert set must still produce a valid (cover-only) document.
    final empty = await buildIncidentReportPdf([]);
    expect(empty.length, greaterThan(1000));

    // Keep a copy for manual inspection when run locally.
    final out = File('${Directory.systemTemp.path}/wirewolf_report_smoke.pdf');
    await out.writeAsBytes(bytes);
  });
}
