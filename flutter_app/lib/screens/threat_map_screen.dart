import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:webview_windows/webview_windows.dart';
import '../ffi/wirewolf_service.dart';
import '../ffi/geo_ip.dart';
import '../theme/app_theme.dart';
import '../panels/host_telemetry.dart';

/// Threat Map — a Three.js (WebGL) globe embedded via WebView2, styled after
/// 2050.earth: textured Earth, clouds, atmosphere glow and animated attack arcs
/// converging on the monitored network. Source locations are approximated
/// offline (see geo_ip.dart). All web assets are bundled — no network needed.
class ThreatMapScreen extends StatefulWidget {
  final List<AlertData> alerts;
  const ThreatMapScreen({super.key, required this.alerts});

  @override
  State<ThreatMapScreen> createState() => _ThreatMapScreenState();
}

class _ThreatMapScreenState extends State<ThreatMapScreen> {
  final _controller = WebviewController();
  bool _ready = false;
  bool _failed = false;
  String _error = '';
  String _lastPayload = '';
  bool _showTargets = false; // side panel: false = attackers, true = targets

  // Page + bundled world geometry. world.js is loaded by index.html via a
  // relative <script> tag (works from file://, unlike fetch/textures).
  static const _assetFiles = ['index.html', 'world.js'];

  @override
  void initState() {
    super.initState();
    _init();
  }

  Future<void> _init() async {
    try {
      final dir = await _extractAssets();
      await _controller.initialize();
      await _controller.setBackgroundColor(const Color(0xFF070B12));
      _controller.loadingState.listen((s) {
        if (s == LoadingState.navigationCompleted) {
          _ready = true;
          _push();
        }
      });
      final url = Uri.file('${dir.path}\\index.html', windows: true).toString();
      await _controller.loadUrl(url);
      if (mounted) setState(() {});
    } catch (e) {
      if (mounted) setState(() {
        _failed = true;
        _error = '$e';
      });
    }
  }

  /// Copy bundled web assets to a temp dir so the WebView can load them (and
  /// their relative resources) from a file:// URL.
  Future<Directory> _extractAssets() async {
    final base =
        Directory('${Directory.systemTemp.path}\\wirewolf_globe');
    await base.create(recursive: true);
    for (final f in _assetFiles) {
      final data = await rootBundle.load('assets/globe/$f');
      final bytes =
          data.buffer.asUint8List(data.offsetInBytes, data.lengthInBytes);
      await File('${base.path}\\$f').writeAsBytes(bytes, flush: true);
    }
    return base;
  }

  String _markersJson() {
    // Attacker → victim graph over EXTERNAL (geolocatable) endpoints only.
    // Internal/LAN IPs have no global location, so they are not plotted on the
    // world map. Each external node is coloured by role: attacker (red) if it
    // was ever an alert source, victim (blue) if ever a destination — a host
    // that does both shows both. Edges (attacker→victim arcs, pulse travelling
    // source→destination) are drawn only when BOTH ends are external.
    final nodes =
        <String, ({double lat, double lng, String place, bool atk, bool tgt})>{};
    final edges = <String, ({double sLat, double sLng, double dLat, double dLng, int sev, int count})>{};

    void touch(String ip, GeoPoint g, {required bool atk}) {
      final p = nodes[ip];
      nodes[ip] = (
        lat: g.lat,
        lng: g.lng,
        place: placeLabel(g),
        atk: (p?.atk ?? false) || atk,
        tgt: (p?.tgt ?? false) || !atk,
      );
    }

    for (final a in widget.alerts) {
      // Only public IPs have a real global location; internal endpoints
      // (geoForIp == null) are omitted from the world map.
      final sg = geoForIp(a.srcIp);
      final dg = geoForIp(a.dstIp);
      if (sg != null) touch(a.srcIp, sg, atk: true);
      if (dg != null) touch(a.dstIp, dg, atk: false);
      // An arc needs both ends placeable; internal↔external shows only the
      // external node (coloured by its role), with no arc to a fake location.
      if (sg != null && dg != null) {
        final ek = '${a.srcIp}>${a.dstIp}';
        final pe = edges[ek];
        edges[ek] = (
          sLat: sg.lat,
          sLng: sg.lng,
          dLat: dg.lat,
          dLng: dg.lng,
          sev: pe == null
              ? a.severityLevel
              : (pe.sev > a.severityLevel ? pe.sev : a.severityLevel),
          count: (pe?.count ?? 0) + 1,
        );
      }
    }

    return jsonEncode({
      'nodes': nodes.entries
          .map((e) => {
                'ip': e.key,
                'lat': e.value.lat,
                'lng': e.value.lng,
                'place': e.value.place,
                'atk': e.value.atk,
                'tgt': e.value.tgt,
              })
          .toList(),
      'edges': edges.values
          .map((e) => {
                'sLat': e.sLat,
                'sLng': e.sLng,
                'dLat': e.dLat,
                'dLng': e.dLng,
                'color': AppColors.severityColor(e.sev).value & 0xFFFFFF,
                'count': e.count,
              })
          .toList(),
    });
  }

  Future<void> _push() async {
    if (!_ready) return;
    final payload = _markersJson();
    if (payload == _lastPayload) return;
    _lastPayload = payload;
    try {
      await _controller
          .executeScript('window.setMarkers && window.setMarkers(${jsonEncode(payload)});');
    } catch (_) {}
  }

  @override
  void didUpdateWidget(ThreatMapScreen old) {
    super.didUpdateWidget(old);
    _push();
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  /// Aggregate alerts by one endpoint (source = attackers, destination =
  /// targets), keeping the highest severity and a count, sorted by count.
  List<({String ip, GeoPoint geo, int count, int sev})> _rank(
      {required bool byTarget}) {
    final byIp = <String, ({int count, int sev, GeoPoint geo})>{};
    for (final a in widget.alerts) {
      final ip = byTarget ? a.dstIp : a.srcIp;
      final prev = byIp[ip];
      byIp[ip] = (
        count: (prev?.count ?? 0) + 1,
        sev: prev == null
            ? a.severityLevel
            : (prev.sev > a.severityLevel ? prev.sev : a.severityLevel),
        geo: endpointGeoFor(ip),
      );
    }
    final list = <({String ip, GeoPoint geo, int count, int sev})>[];
    byIp.forEach((ip, v) {
      list.add((ip: ip, geo: v.geo, count: v.count, sev: v.sev));
    });
    list.sort((a, b) => b.count.compareTo(a.count));
    return list;
  }

  @override
  Widget build(BuildContext context) {
    final ranked = _rank(byTarget: _showTargets);
    final maxVal = ranked.isEmpty ? 1 : ranked.first.count;

    return Padding(
      padding: const EdgeInsets.all(16),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Expanded(flex: 3, child: _globeCard()),
          const SizedBox(width: 16),
          Expanded(flex: 2, child: _originsCard(ranked, maxVal)),
        ],
      ),
    );
  }

  Widget _toggleChip(String label, bool active, VoidCallback onTap) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(6),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 4),
        decoration: BoxDecoration(
          color: active
              ? AppColors.accent.withOpacity(0.14)
              : AppColors.surfaceLight,
          borderRadius: BorderRadius.circular(6),
          border: Border.all(
              color: active ? AppColors.accent : AppColors.border),
        ),
        child: Text(label,
            style: TextStyle(
                fontSize: 10.5,
                fontWeight: FontWeight.w600,
                color: active ? AppColors.accent : AppColors.textMuted)),
      ),
    );
  }

  Widget _globeCard() {
    return Card(
      clipBehavior: Clip.antiAlias,
      child: Container(
        color: const Color(0xFF070B12),
        child: Stack(
          children: [
            if (_failed)
              _fallback()
            else if (!_ready && !_controller.value.isInitialized)
              const Center(
                  child: SizedBox(
                      width: 22,
                      height: 22,
                      child: CircularProgressIndicator(
                          strokeWidth: 2, color: Colors.white24)))
            else
              Positioned.fill(child: Webview(_controller)),
            // Header overlay
            Positioned(
              left: 14,
              top: 12,
              right: 14,
              child: Row(
                children: [
                  const Text('Global Threat Map',
                      style: TextStyle(
                          color: Colors.white,
                          fontSize: 13,
                          fontWeight: FontWeight.w700)),
                  const Spacer(),
                  Text('live · approx geo',
                      style: AppText.mono(
                          size: 9.5, color: Colors.white.withOpacity(0.55))),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _fallback() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.public_off, color: Colors.white30, size: 40),
            const SizedBox(height: 12),
            const Text('Globe unavailable',
                style: TextStyle(
                    color: Colors.white70,
                    fontSize: 13,
                    fontWeight: FontWeight.w600)),
            const SizedBox(height: 6),
            Text(
              'The WebView2 runtime is required to render the 3D globe.\n$_error',
              textAlign: TextAlign.center,
              style: AppText.mono(
                  size: 10, color: Colors.white38, height: 1.5),
            ),
          ],
        ),
      ),
    );
  }

  Widget _originsCard(
      List<({String ip, GeoPoint geo, int count, int sev})> origins,
      int maxVal) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Text(_showTargets ? 'Top Targets' : 'Top Attackers',
                    style: const TextStyle(
                        color: AppColors.textSecondary,
                        fontSize: 12,
                        fontWeight: FontWeight.w600)),
                const Spacer(),
                _toggleChip('Attackers', !_showTargets,
                    () => setState(() => _showTargets = false)),
                const SizedBox(width: 6),
                _toggleChip('Targets', _showTargets,
                    () => setState(() => _showTargets = true)),
              ],
            ),
            const SizedBox(height: 6),
            Text('Tap a row for telemetry',
                style: AppText.mono(size: 9.5, color: AppColors.textMuted)),
            const SizedBox(height: 14),
            if (origins.isEmpty)
              Expanded(
                child: Center(
                  child: Text(
                      _showTargets ? 'No targets yet' : 'No sources yet',
                      style: AppText.mono(
                          size: 11, color: AppColors.textMuted)),
                ),
              )
            else
              Expanded(
                child: ListView(
                  children: origins.take(12).map((o) {
                    final color = AppColors.severityColor(o.sev);
                    return InkWell(
                      onTap: () =>
                          showHostTelemetry(context, o.ip, widget.alerts),
                      borderRadius: BorderRadius.circular(6),
                      child: Padding(
                      padding: const EdgeInsets.only(bottom: 12, top: 2),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              Container(
                                width: 8,
                                height: 8,
                                decoration: BoxDecoration(
                                    color: color, shape: BoxShape.circle),
                              ),
                              const SizedBox(width: 8),
                              Text(placeLabel(o.geo),
                                  style: const TextStyle(
                                      color: AppColors.textPrimary,
                                      fontSize: 12,
                                      fontWeight: FontWeight.w600)),
                              const Spacer(),
                              Text('${o.count}',
                                  style: AppText.mono(
                                      size: 11,
                                      weight: FontWeight.w700,
                                      color: AppColors.textSecondary)),
                            ],
                          ),
                          const SizedBox(height: 4),
                          Row(
                            children: [
                              SizedBox(
                                width: 116,
                                child: Text(o.ip,
                                    style: AppText.mono(
                                        size: 10, color: AppColors.textMuted),
                                    overflow: TextOverflow.ellipsis),
                              ),
                              const SizedBox(width: 8),
                              Expanded(
                                child: ClipRRect(
                                  borderRadius: BorderRadius.circular(2),
                                  child: LinearProgressIndicator(
                                    value: o.count / maxVal,
                                    minHeight: 6,
                                    backgroundColor: AppColors.surfaceLight,
                                    valueColor: AlwaysStoppedAnimation(
                                        color.withOpacity(0.7)),
                                  ),
                                ),
                              ),
                            ],
                          ),
                        ],
                      ),
                    ),
                    );
                  }).toList(),
                ),
              ),
          ],
        ),
      ),
    );
  }
}
