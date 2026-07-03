// Build tool: convert the big IP2Location LITE CSVs into compact binaries the
// app can mmap and binary-search. Run from flutter_app/ with:
//   dart run tool/convert_ip2location.dart
//
// Outputs into assets/geo/:
//   city.bin/.str   — DB11: range -> lat,lng + "city\tcc"
//   asn.bin/.str    — ASN:  range -> asn + as-name
//   proxy.bin/.str  — PX12: range -> "proxyType\tusageType\tthreat\tfraud"
import 'dart:io';
import 'dart:typed_data';

const work = 'assets/geo/work';
const out = 'assets/geo';

// Split a fully-quoted CSV line ("a","b",...) on the `","` boundary so commas
// inside fields don't break it.
List<String> splitCsv(String line) {
  if (line.length < 2) return const [];
  final inner = line.substring(1, line.length - 1); // drop outer quotes
  return inner.split('","');
}

class StrTable {
  final _index = <String, int>{};
  final _list = <String>[];
  int intern(String s) => _index.putIfAbsent(s, () {
        _list.add(s);
        return _list.length - 1;
      });
  void write(String path) =>
      File(path).writeAsStringSync(_list.join('\n'));
}

void convert(String csvPath, String binPath, String strPath, int rowBytes,
    void Function(List<String> f, ByteData row, StrTable str) emit) {
  final strs = StrTable();
  final bb = BytesBuilder(copy: false);
  final scratch = ByteData(rowBytes);
  var rows = 0;
  final raf = File(csvPath).openSync();
  final reader = _LineReader(raf);
  String? line;
  while ((line = reader.next()) != null) {
    final f = splitCsv(line!);
    if (f.length < 2) continue;
    emit(f, scratch, strs);
    bb.add(Uint8List.fromList(scratch.buffer.asUint8List(0, rowBytes)));
    rows++;
  }
  raf.closeSync();
  File(binPath).writeAsBytesSync(bb.takeBytes());
  strs.write(strPath);
  print('  $csvPath -> $rows rows, ${File(binPath).lengthSync() ~/ (1024*1024)} MB');
}

// Minimal buffered line reader (avoids async; CSVs are ASCII).
class _LineReader {
  final RandomAccessFile _raf;
  final _buf = <int>[];
  Uint8List _chunk = Uint8List(0);
  int _pos = 0;
  _LineReader(this._raf);
  String? next() {
    while (true) {
      if (_pos >= _chunk.length) {
        _chunk = _raf.readSync(1 << 20);
        _pos = 0;
        if (_chunk.isEmpty) {
          if (_buf.isEmpty) return null;
          final s = String.fromCharCodes(_buf);
          _buf.clear();
          return s;
        }
      }
      while (_pos < _chunk.length) {
        final c = _chunk[_pos++];
        if (c == 10) {
          var s = String.fromCharCodes(_buf);
          _buf.clear();
          if (s.endsWith('\r')) s = s.substring(0, s.length - 1);
          return s;
        }
        _buf.add(c);
      }
    }
  }
}

void main() {
  // DB11 city: from,to,cc,country,region,city,lat,lng,zip,tz
  convert('$work/DB11/IP2LOCATION-LITE-DB11.CSV', '$out/city.bin', '$out/city.str',
      20, (f, row, str) {
    row.setUint32(0, int.parse(f[0]), Endian.little);
    row.setUint32(4, int.parse(f[1]), Endian.little);
    row.setFloat32(8, double.tryParse(f[6]) ?? 0, Endian.little);
    row.setFloat32(12, double.tryParse(f[7]) ?? 0, Endian.little);
    final cc = f[2] == '-' ? '' : f[2];
    final city = f[5] == '-' ? (f[3] == '-' ? '' : f[3]) : f[5];
    row.setUint32(16, str.intern('$city\t$cc'), Endian.little);
  });

  // ASN: from,to,cidr,asn,as_name
  convert('$work/ASN/IP2LOCATION-LITE-ASN.CSV', '$out/asn.bin', '$out/asn.str',
      16, (f, row, str) {
    row.setUint32(0, int.parse(f[0]), Endian.little);
    row.setUint32(4, int.parse(f[1]), Endian.little);
    row.setUint32(8, int.tryParse(f[3]) ?? 0, Endian.little);
    final name = f[4] == '-' ? '' : f[4];
    row.setUint32(12, str.intern(name), Endian.little);
  });

  // PX12: from,to,proxy_type,cc,country,region,city,isp,domain,usage_type,asn,as,last_seen,threat,provider,fraud
  convert('$work/PX12/IP2PROXY-LITE-PX12.CSV', '$out/proxy.bin', '$out/proxy.str',
      12, (f, row, str) {
    row.setUint32(0, int.parse(f[0]), Endian.little);
    row.setUint32(4, int.parse(f[1]), Endian.little);
    final ptype = f.length > 2 ? f[2] : '-';
    final usage = f.length > 9 ? f[9] : '-';
    final threat = f.length > 13 ? f[13] : '-';
    final fraud = f.length > 15 ? f[15] : '-';
    row.setUint32(8, str.intern('$ptype\t$usage\t$threat\t$fraud'), Endian.little);
  });

  print('done');
}
