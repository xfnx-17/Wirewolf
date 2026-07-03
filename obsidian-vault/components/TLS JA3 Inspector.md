---
title: TLS JA3 Inspector
type: component
tags: [component, backend, threat-intel]
status: documented
created: 2026-06-26
module: "Threat Intelligence"
---
# TLS JA3 Inspector

Inspects TLS handshakes **without decrypting them**. From the ClientHello it extracts the SNI (destination hostname) and computes a **JA3** fingerprint of the client's TLS stack, then checks both against the threat feed.

## How it works
1. The pre-filter calls `inspect_tls(flow)` when a flow looks like a TLS handshake.
2. It parses the ClientHello and builds the JA3 string from: TLS version, accepted cipher suites, extensions, elliptic curves, and EC point formats — joined and **MD5-hashed** (the standard JA3 construction). See [[JA3 Fingerprinting]].
3. It checks the JA3 against `bad_ja3.txt` and the SNI against `bad_domains.txt` via [[Threat Feed & Rules]].
4. Return codes drive the pre-filter:
   - `0` = not TLS → normal handling
   - `1` = TLS **suspicious** (bad JA3, or DGA/raw-IP SNI) → `protocol_tag` set, escalate
   - `2` = TLS **benign** → drop (the encrypted payload is useless to the LLM)
5. Exploits riding on TLS (e.g. Heartbleed) are checked **before** dropping as benign, so the fast-path can't mask them.

## Why fingerprinting beats payload inspection here
TLS payloads are encrypted, so content rules see nothing. JA3 identifies the *client software* from the handshake shape — many malware families have distinctive, reusable JA3s, so a match flags malicious clients even over HTTPS.

## Key Files
- `include/tls_inspector.hpp`, `src/npu_filter.cpp` (`inspect_tls`), `rules/bad_ja3.txt`

## Module
[[Threat Intelligence]]

## Dependencies
[[Threat Feed & Rules]]

## Used By
[[TCP Reassembler]]

## Related
[[JA3 Fingerprinting]]

---
#component #backend #threat-intel
