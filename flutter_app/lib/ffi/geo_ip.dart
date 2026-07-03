import 'ip2location.dart';

/// Offline IP geolocation.
///
/// Real geolocation is provided by [GeoIpDb], which loads the bundled
/// IP2Location LITE DB11 (city) database and resolves a public IP to its city,
/// country and lat/lng. Until it finishes loading — and for private/LAN
/// addresses, which have no public location — we fall back to a deterministic
/// hash onto a small city list so the map still populates.
class GeoPoint {
  final double lat;
  final double lng;
  final String city; // most specific name: city/state, or '' if only country
  final String cc; // ISO country code
  final String country; // country name (for display when no city)
  const GeoPoint(this.lat, this.lng, this.city, this.cc, {this.country = ''});
}

/// The geolocatable (public) endpoint of an alert and its location. For an
/// outbound flow (internal src → public dst) this is the destination — the
/// threat infrastructure worth placing on a map; for an inbound flow it's the
/// source. Returns null when BOTH endpoints are private/internal (no location).
({String ip, GeoPoint geo})? externalEndpoint(String srcIp, String dstIp) {
  for (final ip in [srcIp, dstIp]) {
    final o = _octets(ip);
    if (o == null || _isPrivate(o)) continue;
    final g = GeoIpDb.ready ? GeoIpDb.lookupOctets(o) : null;
    return (ip: ip, geo: g ?? _cityForOctets(o));
  }
  return null;
}

/// Geolocate ANY endpoint for the attacker/victim graph: public IPs resolve to
/// their city; private/internal IPs are placed near the monitored site
/// ([kHome]), deterministically jittered so distinct LAN hosts don't all stack
/// on one pixel. Always returns a point (never null).
GeoPoint endpointGeoFor(String ip) {
  final o = _octets(ip);
  if (o == null) return kHome;
  if (_isPrivate(o)) {
    // ±~0.7° jitter around home, stable per host.
    final jLat = ((o[2] * 256 + o[3]) % 140 - 70) / 100.0;
    final jLng = ((o[0] * 256 + o[1]) % 140 - 70) / 100.0;
    return GeoPoint(kHome.lat + jLat, kHome.lng + jLng, 'Internal (LAN)', '');
  }
  if (GeoIpDb.ready) {
    final g = GeoIpDb.lookupOctets(o);
    if (g != null) return g;
  }
  return _cityForOctets(o);
}

/// ISP / ASN label for an IP, e.g. "Anthropic PBC · AS399358", or '—'.
String ispLabelFor(String ip) {
  final o = _octets(ip);
  if (o == null) return '—';
  final a = Ip2Loc.asn(o);
  if (a == null) return '—';
  if (a.asn > 0) {
    return a.name.isEmpty ? 'AS${a.asn}' : '${a.name} · AS${a.asn}';
  }
  return a.name.isEmpty ? '—' : a.name;
}

/// Anonymizer label for an IP from the proxy DB: "No" if not a known proxy,
/// else the proxy type (VPN/TOR/DCH/…) plus any threat tag.
String anonLabelFor(String ip) {
  final o = _octets(ip);
  if (o == null) return '—';
  final p = Ip2Loc.proxy(o);
  if (p == null) return 'No';
  final threat = (p.threat != '-' && p.threat.isNotEmpty) ? ' · ${p.threat}' : '';
  return '${p.type}$threat';
}

/// Curated threat tag for an IP (PX12: SPAM/BOTNET/SCANNER), or '' if none.
/// These are IPs IP2Location flagged as actual malicious infrastructure — a
/// high-precision signal (unlike "is a proxy", which is everywhere legitimately).
String threatTagFor(String ip) {
  final o = _octets(ip);
  if (o == null) return '';
  final p = Ip2Loc.proxy(o);
  if (p == null) return '';
  return (p.threat != '-' && p.threat.isNotEmpty) ? p.threat : '';
}

/// True if the IP is a Tor exit / VPN / open-or-web proxy (anonymized origin).
/// Datacenter (DCH) hosting is NOT treated as an anonymizer — too common.
bool isAnonymizerIp(String ip) {
  final o = _octets(ip);
  if (o == null) return false;
  final p = Ip2Loc.proxy(o);
  return p != null && p.isAnonymizer;
}

/// Display label: "City, CC" when a city/state is known, otherwise just the
/// country name (so country-only records don't render "United States, US").
String placeLabel(GeoPoint g) {
  if (g.city.isNotEmpty) {
    return g.cc.isNotEmpty ? '${g.city}, ${g.cc}' : g.city;
  }
  if (g.country.isNotEmpty) return g.country;
  return g.cc.isNotEmpty ? g.cc : 'Unknown';
}

/// Coordinates of the monitored network ("home"); arcs converge here.
/// Set to the operator's site — adjust to your actual location.
const GeoPoint kHome = GeoPoint(4.60, 101.09, 'Perak', 'MY');

const List<GeoPoint> _cities = [
  GeoPoint(52.37, 4.90, 'Amsterdam', 'NL'),
  GeoPoint(55.75, 37.62, 'Moscow', 'RU'),
  GeoPoint(44.43, 26.10, 'Bucharest', 'RO'),
  GeoPoint(22.32, 114.17, 'Hong Kong', 'HK'),
  GeoPoint(1.35, 103.82, 'Singapore', 'SG'),
  GeoPoint(-23.55, -46.63, 'São Paulo', 'BR'),
  GeoPoint(19.07, 72.87, 'Mumbai', 'IN'),
  GeoPoint(6.52, 3.37, 'Lagos', 'NG'),
  GeoPoint(39.90, 116.40, 'Beijing', 'CN'),
  GeoPoint(35.68, 139.69, 'Tokyo', 'JP'),
  GeoPoint(51.51, -0.13, 'London', 'GB'),
  GeoPoint(48.85, 2.35, 'Paris', 'FR'),
  GeoPoint(50.11, 8.68, 'Frankfurt', 'DE'),
  GeoPoint(40.71, -74.01, 'New York', 'US'),
  GeoPoint(37.77, -122.42, 'San Francisco', 'US'),
  GeoPoint(-33.87, 151.21, 'Sydney', 'AU'),
  GeoPoint(25.20, 55.27, 'Dubai', 'AE'),
  GeoPoint(31.23, 121.47, 'Shanghai', 'CN'),
  GeoPoint(37.57, 126.98, 'Seoul', 'KR'),
  GeoPoint(-26.20, 28.04, 'Johannesburg', 'ZA'),
  GeoPoint(19.43, -99.13, 'Mexico City', 'MX'),
  GeoPoint(41.01, 28.98, 'Istanbul', 'TR'),
  GeoPoint(59.33, 18.07, 'Stockholm', 'SE'),
  GeoPoint(1.29, 103.85, 'Kuala Lumpur', 'MY'),
];

List<int>? _octets(String ip) {
  final parts = ip.split('.');
  if (parts.length != 4) return null;
  final o = <int>[];
  for (final p in parts) {
    final v = int.tryParse(p);
    if (v == null || v < 0 || v > 255) return null;
    o.add(v);
  }
  return o;
}

bool _isPrivate(List<int> o) {
  if (o[0] == 10 || o[0] == 127 || o[0] == 0) return true;
  if (o[0] == 192 && o[1] == 168) return true;
  if (o[0] == 172 && o[1] >= 16 && o[1] <= 31) return true;
  if (o[0] == 169 && o[1] == 254) return true;
  return false;
}

GeoPoint _cityForOctets(List<int> octets) {
  var h = 2166136261;
  for (final b in octets) {
    h = (h ^ b) * 16777619;
    h &= 0xFFFFFFFF;
  }
  return _cities[h % _cities.length];
}

/// Real (DB-backed) location for a public IPv4, or null for private/loopback
/// addresses or when the DB hasn't loaded / has no entry. Falls back to the
/// hash approximation only while the DB is still loading.
GeoPoint? geoForIp(String ip) {
  final octets = _octets(ip);
  if (octets == null) return null;
  if (_isPrivate(octets)) return null;
  if (GeoIpDb.ready) return GeoIpDb.lookupOctets(octets);
  return _cityForOctets(octets);
}

/// Always returns a place for display. Uses the real DB for public IPs; for
/// private/internal addresses (no public geolocation) or DB misses it returns
/// the hash approximation so the UI shows a location rather than "Internal".
GeoPoint geoForIpLabel(String ip) {
  final octets = _octets(ip);
  if (octets != null && !_isPrivate(octets) && GeoIpDb.ready) {
    final g = GeoIpDb.lookupOctets(octets);
    if (g != null) return g;
  }
  return _cityForOctets(octets ?? const [0, 0, 0, 0]);
}

/// Loads and queries the offline IP2Location LITE databases (city/ASN/proxy).
class GeoIpDb {
  static bool get ready => Ip2Loc.ready;

  static Future<void> load() => Ip2Loc.load();

  static GeoPoint? lookupOctets(List<int> o) {
    final c = Ip2Loc.city(o);
    if (c == null) return null;
    // city already includes the country name when no city is present
    return GeoPoint(c.lat, c.lng, c.city, c.cc, country: c.city);
  }
}
