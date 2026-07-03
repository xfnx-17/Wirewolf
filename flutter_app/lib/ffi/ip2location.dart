import 'dart:typed_data';
import 'package:flutter/services.dart' show rootBundle;

/// Reader for the preprocessed IP2Location LITE binaries (see
/// tool/convert_ip2location.dart). Each binary is rows sorted by start-IP:
///   [start u32][end u32][payload...]  (little-endian)
/// with a parallel '\n'-joined string table for deduped text fields.
/// Lookups are an O(log n) binary search over the start-IP column.
class _RangeDb {
  ByteData? _b;
  int _rows = 0;
  final int rowBytes;
  List<String> _str = const [];
  _RangeDb(this.rowBytes);

  Future<void> load(String bin, String str) async {
    _b = await rootBundle.load(bin);
    _rows = _b!.lengthInBytes ~/ rowBytes;
    _str = (await rootBundle.loadString(str)).split('\n');
  }

  bool get ready => _b != null && _rows > 0;

  /// Returns the row offset whose [start,end] contains [ip], or -1.
  int find(int ip) {
    final b = _b;
    if (b == null) return -1;
    var lo = 0, hi = _rows - 1, ans = -1;
    while (lo <= hi) {
      final mid = (lo + hi) >> 1;
      final start = b.getUint32(mid * rowBytes, Endian.little);
      if (start <= ip) {
        ans = mid;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    if (ans < 0) return -1;
    final off = ans * rowBytes;
    if (ip > b.getUint32(off + 4, Endian.little)) return -1; // past range end
    return off;
  }

  int u32(int off) => _b!.getUint32(off, Endian.little);
  double f32(int off) => _b!.getFloat32(off, Endian.little);
  String strAt(int idx) => (idx >= 0 && idx < _str.length) ? _str[idx] : '';
}

class IpCity {
  final double lat, lng;
  final String city, cc;
  const IpCity(this.lat, this.lng, this.city, this.cc);
}

class IpAsn {
  final int asn;
  final String name;
  const IpAsn(this.asn, this.name);
}

class IpProxy {
  final String type; // VPN/TOR/PUB/WEB/DCH/...
  final String usage; // DCH/ISP/...
  final String threat; // SPAM/BOTNET/SCANNER/- ...
  final String fraud; // 0-100 score (string)
  const IpProxy(this.type, this.usage, this.threat, this.fraud);
  bool get isAnonymizer => type == 'VPN' || type == 'TOR' || type == 'PUB' ||
      type == 'WEB' || type == 'RES';
}

/// Offline IP enrichment from the bundled IP2Location LITE binaries:
/// city geolocation (DB11), ASN/ISP (ASN), and proxy/anonymizer (PX12).
class Ip2Loc {
  static final _city = _RangeDb(20);
  static final _asn = _RangeDb(16);
  static final _proxy = _RangeDb(12);
  static bool ready = false;

  static int ipNum(List<int> o) =>
      o[0] * 16777216 + o[1] * 65536 + o[2] * 256 + o[3];

  static Future<void> load() async {
    try {
      await _city.load('assets/geo/city.bin', 'assets/geo/city.str');
      await _asn.load('assets/geo/asn.bin', 'assets/geo/asn.str');
      await _proxy.load('assets/geo/proxy.bin', 'assets/geo/proxy.str');
      ready = _city.ready;
    } catch (_) {
      ready = false;
    }
  }

  static IpCity? city(List<int> o) {
    if (!_city.ready) return null;
    final off = _city.find(ipNum(o));
    if (off < 0) return null;
    final lat = _city.f32(off + 8), lng = _city.f32(off + 12);
    final parts = _city.strAt(_city.u32(off + 16)).split('\t');
    final c = parts.isNotEmpty ? parts[0] : '';
    final cc = parts.length > 1 ? parts[1] : '';
    if (lat == 0 && lng == 0 && c.isEmpty) return null;
    return IpCity(lat, lng, c, cc);
  }

  static IpAsn? asn(List<int> o) {
    if (!_asn.ready) return null;
    final off = _asn.find(ipNum(o));
    if (off < 0) return null;
    final n = _asn.u32(off + 8);
    final name = _asn.strAt(_asn.u32(off + 12));
    if (n == 0 && name.isEmpty) return null;
    return IpAsn(n, name);
  }

  static IpProxy? proxy(List<int> o) {
    if (!_proxy.ready) return null;
    final off = _proxy.find(ipNum(o));
    if (off < 0) return null; // not in any proxy range = not a known proxy
    final p = _proxy.strAt(_proxy.u32(off + 8)).split('\t');
    return IpProxy(
      p.isNotEmpty ? p[0] : '-',
      p.length > 1 ? p[1] : '-',
      p.length > 2 ? p[2] : '-',
      p.length > 3 ? p[3] : '-',
    );
  }
}
