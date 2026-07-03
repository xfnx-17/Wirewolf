import '../ffi/wirewolf_service.dart';
import '../ffi/geo_ip.dart';

/// Plain-English, deterministic explanation of a single alert — the "explainer"
/// role of the two-mode design, rendered app-side so every alert (rule-,
/// anomaly-, or LLM-decided) gets a human-readable narrative without an extra
/// model call. A future enhancement is to replace this with an in-engine LLM
/// narration pass in Forensic mode (see the Operating Modes design note).
String explainAlert(AlertData a) {
  final src = '${a.srcIp}:${a.srcPort}';
  final dst = '${a.dstIp}:${a.dstPort}';
  final ev = a.snippet.trim();
  final evidence = ev.isEmpty
      ? ''
      : ' Evidence: "${ev.length > 160 ? '${ev.substring(0, 160)}…' : ev}".';

  String why;
  switch (a.threatType) {
    case 'SQLi':
      why = 'A SQL injection payload was sent to $dst, attempting to tamper with '
          'a database query — often to read or modify data it should not.';
      break;
    case 'XSS':
      why = 'A cross-site scripting payload was sent to $dst, trying to inject '
          'script that would run in a victim\'s browser.';
      break;
    case 'Command Injection':
      why = '$src tried to run operating-system commands on $dst by injecting '
          'shell syntax into an input.';
      break;
    case 'Log4Shell':
      why = 'A Log4Shell (CVE-2021-44228) JNDI lookup was sent to $dst, which can '
          'make the server fetch and execute attacker-controlled code.';
      break;
    case 'Shellshock':
      why = 'A Shellshock payload was sent to $dst, exploiting a Bash parsing flaw '
          'to execute commands.';
      break;
    case 'Path Traversal':
      why = '$src attempted to escape the web root on $dst (../) to read files '
          'outside the intended directory.';
      break;
    case 'XXE':
      why = 'An XML External Entity payload was sent to $dst, attempting to read '
          'local files or reach internal services.';
      break;
    case 'SSRF':
      why = '$src tried to make $dst issue requests to an internal/metadata '
          'address (server-side request forgery).';
      break;
    case 'Reverse Shell':
      why = 'A reverse-shell pattern was seen from $src — a compromised host '
          'calling back to give the attacker interactive control.';
      break;
    case 'Port Scan':
    case 'Vulnerability Scanning':
      why = '$src probed many ports/paths on the network — reconnaissance that '
          'usually precedes an attack.';
      break;
    case 'Worm Propagation Scan':
      why = '$src scanned many hosts on the same service port — behavior typical '
          'of a self-propagating worm.';
      break;
    case 'SSH Brute Force':
      why = '$src made many rapid SSH authentication attempts against $dst — a '
          'password brute-force.';
      break;
    case 'Brute Force':
      why = '$src made many rapid authentication attempts against $dst.';
      break;
    case 'DDoS':
      why = '$src sent a flood of traffic to $dst at a rate consistent with a '
          'denial-of-service attempt.';
      break;
    case 'C2 Beaconing':
    case 'RAT C2':
    case 'Botnet Host':
      why = '$src showed command-and-control communication with $dst — a likely '
          'sign the internal host is compromised and taking orders.';
      break;
    case 'Cryptominer Traffic':
      why = '$src spoke a mining protocol to $dst — likely unauthorized '
          'cryptocurrency mining.';
      break;
    case 'Data Exfiltration':
      why = '$src transferred data out to the external host $dst in a way '
          'consistent with exfiltration.';
      break;
    case 'Credential Theft':
      why = 'Credential-dumping content was seen from $src toward $dst.';
      break;
    case 'Heartbleed':
      why = 'A Heartbleed (CVE-2014-0160) pattern targeted $dst, which can leak '
          'memory contents including keys.';
      break;
    default:
      why = 'Suspicious activity classified as "${a.threatType}" was observed '
          'from $src to $dst.';
  }

  // Threat-intel / anonymizer context on the external endpoint, if any.
  final ext = externalEndpoint(a.srcIp, a.dstIp);
  String ctx = '';
  if (ext != null) {
    final tag = threatTagFor(ext.ip);
    final isp = ispLabelFor(ext.ip);
    final place = placeLabel(ext.geo);
    final bits = <String>[];
    bits.add('external endpoint ${ext.ip} is in $place');
    if (isp != '—') bits.add('on $isp');
    if (tag.isNotEmpty) bits.add('flagged as $tag by threat intel');
    ctx = ' (${bits.join(', ')}).';
  }

  return '$why$ctx Severity ${a.severity} (CVSS ${a.cvss.toStringAsFixed(1)}).$evidence';
}

/// Build a Markdown incident report from the current alert set — the Forensic
/// deliverable ("what happened in this capture?").
String buildIncidentReport(List<AlertData> alerts) {
  final now = DateTime.now();
  final b = StringBuffer();
  b.writeln('# Wirewolf Incident Report');
  b.writeln();
  b.writeln('_Generated ${now.toIso8601String()}_');
  b.writeln();

  if (alerts.isEmpty) {
    b.writeln('No alerts in the current session.');
    return b.toString();
  }

  // Summary by severity.
  final bySev = <String, int>{};
  for (final a in alerts) {
    bySev[a.severity] = (bySev[a.severity] ?? 0) + 1;
  }
  b.writeln('## Summary');
  b.writeln();
  b.writeln('- Total alerts: ${alerts.length}');
  for (final s in ['Critical', 'High', 'Medium', 'Low', 'Info']) {
    if (bySev[s] != null) b.writeln('- $s: ${bySev[s]}');
  }
  b.writeln();

  // Top attackers / targets.
  final atk = <String, int>{};
  final tgt = <String, int>{};
  for (final a in alerts) {
    atk[a.srcIp] = (atk[a.srcIp] ?? 0) + 1;
    tgt[a.dstIp] = (tgt[a.dstIp] ?? 0) + 1;
  }
  String topLine(Map<String, int> m) {
    final e = m.entries.toList()..sort((x, y) => y.value.compareTo(x.value));
    return e.take(5).map((x) => '${x.key} (${x.value})').join(', ');
  }
  b.writeln('## Key hosts');
  b.writeln();
  b.writeln('- Top sources: ${topLine(atk)}');
  b.writeln('- Top targets: ${topLine(tgt)}');
  b.writeln();

  // Timeline of alerts with explanations.
  final sorted = [...alerts]..sort((a, b) => a.timestamp.compareTo(b.timestamp));
  b.writeln('## Alerts (chronological)');
  b.writeln();
  for (var i = 0; i < sorted.length; i++) {
    final a = sorted[i];
    final t = a.timestamp.toIso8601String().substring(11, 19);
    b.writeln('### ${i + 1}. [$t] ${a.threatType} — ${a.severity}');
    b.writeln();
    b.writeln('- Source: ${a.srcIp}:${a.srcPort}');
    b.writeln('- Target: ${a.dstIp}:${a.dstPort}');
    b.writeln('- CVSS: ${a.cvss.toStringAsFixed(1)}');
    b.writeln();
    b.writeln(explainAlert(a));
    b.writeln();
  }
  return b.toString();
}
