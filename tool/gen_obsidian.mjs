// Generates linked Obsidian notes from a Wirewolf alert set so the vault's
// Graph View shows attackers ↔ threat types ↔ targets. Writes under
// <vault>/Wirewolf/. Run: node tool/gen_obsidian.mjs "<vault path>"
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';

const vault = process.argv[2] || 'D:\\SideProject\\side project';
const root = join(vault, 'Wirewolf');
const hostsDir = join(root, 'hosts');
const threatsDir = join(root, 'threats');

const SEV = ['Info', 'Low', 'Medium', 'High', 'Critical'];

// [type, sevLevel, cvss, srcIp, dstIp, dstPort, snippet]
const alerts = [
  ['SQLi', 4, 9.3, '10.0.0.50', '192.168.1.5', 80, "' OR '1'='1"],
  ['SQLi', 4, 9.3, '10.0.0.50', '192.168.1.5', 80, 'UNION SELECT * FROM users--'],
  ['Port Scan', 2, 6.9, '10.0.0.100', '192.168.1.1', 0, '52 unique ports scanned'],
  ['XSS', 2, 5.3, '10.0.0.50', '192.168.1.5', 80, '<script>alert(1)</script>'],
  ['Log4Shell', 4, 10.0, '10.0.0.50', '192.168.1.20', 8080, 'jndi:ldap exploit'],
  ['Log4Shell', 4, 10.0, '10.0.0.51', '192.168.1.20', 8080, 'jndi:rmi exploit'],
  ['Data Exfiltration', 4, 9.3, '10.2.3.101', '162.241.123.75', 47037, 'Username: victim@gmail.com'],
  ['SSH Brute Force', 3, 7.7, '10.0.0.200', '192.168.1.10', 22, '45 SSH connection attempts'],
  ['SSH Brute Force', 3, 7.7, '10.0.0.201', '192.168.1.10', 22, '38 SSH connection attempts'],
  ['Command Injection', 4, 9.3, '10.0.0.50', '192.168.1.5', 80, ';cat /etc/passwd'],
  ['Reverse Shell', 4, 9.3, '10.0.0.50', '192.168.1.5', 80, 'bash -i >& /dev/tcp/...'],
  ['C2 Beaconing', 4, 9.3, '192.168.1.100', '45.76.33.10', 8443, 'C2 beaconing to 45.76.33.10:8443'],
  ['Path Traversal', 3, 8.7, '10.0.0.50', '192.168.1.5', 80, '../../../../etc/passwd'],
  ['Cryptominer Traffic', 3, 8.7, '192.168.1.100', '45.76.33.10', 3333, 'mining.subscribe'],
  ['DDoS', 3, 8.7, '10.0.0.200', '192.168.1.5', 80, '8500 SYN packets at 120 SYN/sec'],
  ['Directory Enumeration', 2, 6.9, '10.0.0.50', '192.168.1.5', 80, '/.env, /.git/config'],
  ['XXE', 3, 8.7, '10.0.0.50', '192.168.1.5', 80, 'ENTITY xxe SYSTEM file:///etc/passwd'],
  ['SSTI', 4, 9.3, '10.0.0.50', '192.168.1.5', 80, '{{7*7}}'],
  ['Credential Theft', 4, 9.3, '10.0.0.50', '192.168.1.30', 445, 'sekurlsa::logonpasswords'],
  ['Vulnerability Scanning', 2, 6.9, '10.0.0.50', '192.168.1.5', 80, 'Nikto/2.1.6'],
  ['SSRF', 3, 8.7, '10.0.0.50', '192.168.1.5', 80, 'http://169.254.169.254/latest/meta-data/'],
  ['Shellshock', 4, 9.3, '10.0.0.50', '192.168.1.5', 80, '() { :;}; /bin/bash -c'],
  ['Worm Propagation Scan', 4, 10.0, '10.0.0.200', '192.168.1.1', 445, '150 hosts scanned on port 445'],
  ['RAT C2', 4, 9.3, '192.168.1.100', '45.76.33.10', 5552, 'njRAT C2 on 45.76.33.10:5552'],
];

const isPrivate = (ip) =>
  /^10\./.test(ip) || /^192\.168\./.test(ip) ||
  /^172\.(1[6-9]|2\d|3[01])\./.test(ip) || /^127\./.test(ip);

// Build per-host and per-threat aggregates.
const hosts = new Map(); // ip -> {atk:Set, tgt:Set(threat), peersOut:Set, peersIn:Set, threats:Set, worst}
const threats = new Map(); // type -> {srcs:Set, dsts:Set, worst, cvss}

const host = (ip) => {
  if (!hosts.has(ip))
    hosts.set(ip, { atk: 0, tgt: 0, peersOut: new Set(), peersIn: new Set(), threats: new Set(), worst: 0 });
  return hosts.get(ip);
};

for (const [type, sev, cvss, src, dst, port] of alerts) {
  const s = host(src), d = host(dst);
  s.atk++; d.tgt++;
  s.peersOut.add(dst); d.peersIn.add(src);
  s.threats.add(type); d.threats.add(type);
  s.worst = Math.max(s.worst, sev); d.worst = Math.max(d.worst, sev);
  if (!threats.has(type)) threats.set(type, { srcs: new Set(), dsts: new Set(), worst: sev, cvss });
  const t = threats.get(type);
  t.srcs.add(src); t.dsts.add(dst); t.worst = Math.max(t.worst, sev); t.cvss = Math.max(t.cvss, cvss);
}

// Fresh output dir.
rmSync(root, { recursive: true, force: true });
mkdirSync(hostsDir, { recursive: true });
mkdirSync(threatsDir, { recursive: true });

const link = (s) => `[[${s}]]`;

// Host notes.
for (const [ip, h] of hosts) {
  const role = h.atk && h.tgt ? 'attacker + target' : h.atk ? 'attacker' : 'target';
  const scope = isPrivate(ip) ? 'internal' : 'external';
  const lines = [];
  lines.push('---');
  lines.push(`type: host`);
  lines.push(`ip: "${ip}"`);
  lines.push(`role: ${role}`);
  lines.push(`scope: ${scope}`);
  lines.push(`severity: ${SEV[h.worst]}`);
  lines.push('---');
  lines.push(`# ${ip}`);
  lines.push('');
  lines.push(`**Role:** ${role} · **Scope:** ${scope} · **Peak severity:** ${SEV[h.worst]}`);
  lines.push(`**As attacker (source):** ${h.atk} alert(s) · **As target (destination):** ${h.tgt} alert(s)`);
  lines.push('');
  lines.push('## Threat types');
  lines.push([...h.threats].map(link).join(' · ') || '—');
  lines.push('');
  if (h.peersOut.size) {
    lines.push('## Attacked');
    lines.push([...h.peersOut].map(link).join(' · '));
    lines.push('');
  }
  if (h.peersIn.size) {
    lines.push('## Attacked by');
    lines.push([...h.peersIn].map(link).join(' · '));
    lines.push('');
  }
  writeFileSync(join(hostsDir, `${ip}.md`), lines.join('\n'));
}

// Threat notes.
for (const [type, t] of threats) {
  const lines = [];
  lines.push('---');
  lines.push(`type: threat`);
  lines.push(`severity: ${SEV[t.worst]}`);
  lines.push(`cvss: ${t.cvss}`);
  lines.push('---');
  lines.push(`# ${type}`);
  lines.push('');
  lines.push(`**Severity:** ${SEV[t.worst]} · **CVSS:** ${t.cvss}`);
  lines.push('');
  lines.push('## Sources (attackers)');
  lines.push([...t.srcs].map(link).join(' · '));
  lines.push('');
  lines.push('## Targets (victims)');
  lines.push([...t.dsts].map(link).join(' · '));
  lines.push('');
  writeFileSync(join(threatsDir, `${type}.md`), lines.join('\n'));
}

// Index note.
const idx = [];
idx.push('---');
idx.push('type: index');
idx.push('---');
idx.push('# Wirewolf — Threat Overview');
idx.push('');
idx.push(`Generated from ${alerts.length} alerts · ${hosts.size} hosts · ${threats.size} threat types.`);
idx.push('');
idx.push('## Threat types');
idx.push([...threats.keys()].map(link).join(' · '));
idx.push('');
idx.push('## Hosts');
idx.push([...hosts.keys()].map(link).join(' · '));
idx.push('');
writeFileSync(join(root, 'Threat Overview.md'), idx.join('\n'));

console.log(`Wrote ${hosts.size} host notes, ${threats.size} threat notes + index to ${root}`);
