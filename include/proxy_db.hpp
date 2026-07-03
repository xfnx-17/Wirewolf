#pragma once
// Reader for the preprocessed IP2Location PX12 proxy binary (see
// flutter_app/tool/convert_ip2location.dart). Rows are sorted by start-IP:
//   [start u32][end u32][strIdx u32]   (little-endian, 12 bytes)
// with a '\n'-joined string table whose entries are
//   "proxyType\tusageType\tthreat\tfraud".
// Lookup is an O(log n) binary search over the start-IP column. IPs are the
// IP2Location numbering: host-order uint32 (o0*2^24 + o1*2^16 + o2*2^8 + o3).
#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

class ProxyDb {
public:
  struct Info {
    std::string type;   // VPN/TOR/PUB/WEB/DCH/RES/...
    std::string usage;  // DCH/ISP/...
    std::string threat; // BOTNET/SCANNER/SPAM/- ...
  };

  // binPath ends in .bin; the string table is the same path with .str.
  bool load(const std::string &binPath) {
    std::ifstream f(binPath, std::ios::binary);
    if (!f)
      return false;
    f.seekg(0, std::ios::end);
    const std::streamoff sz = f.tellg();
    f.seekg(0);
    if (sz < 12)
      return false;
    data_.resize(static_cast<size_t>(sz));
    f.read(reinterpret_cast<char *>(data_.data()), sz);
    rows_ = data_.size() / 12;

    const auto dot = binPath.find_last_of('.');
    const std::string strPath =
        (dot == std::string::npos ? binPath : binPath.substr(0, dot)) + ".str";
    std::ifstream sf(strPath, std::ios::binary);
    if (sf) {
      const std::string all((std::istreambuf_iterator<char>(sf)),
                            std::istreambuf_iterator<char>());
      size_t pos = 0;
      while (pos <= all.size()) {
        const size_t nl = all.find('\n', pos);
        if (nl == std::string::npos) {
          strs_.push_back(all.substr(pos));
          break;
        }
        strs_.push_back(all.substr(pos, nl - pos));
        pos = nl + 1;
      }
    }
    ready_ = rows_ > 0 && !strs_.empty();
    return ready_;
  }

  bool ready() const { return ready_; }

  // ip = host-order IP2Location numbering (use ntohl on a network-order addr).
  bool lookup(uint32_t ip, Info &out) const {
    if (!ready_)
      return false;
    long lo = 0, hi = static_cast<long>(rows_) - 1, ans = -1;
    while (lo <= hi) {
      const long mid = (lo + hi) / 2;
      if (u32(static_cast<size_t>(mid) * 12) <= ip) {
        ans = mid;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    if (ans < 0)
      return false;
    const size_t off = static_cast<size_t>(ans) * 12;
    if (ip > u32(off + 4))
      return false; // past range end
    const uint32_t idx = u32(off + 8);
    if (idx >= strs_.size())
      return false;
    const std::string &s = strs_[idx];
    const size_t t1 = s.find('\t');
    const size_t t2 = (t1 == std::string::npos) ? t1 : s.find('\t', t1 + 1);
    const size_t t3 = (t2 == std::string::npos) ? t2 : s.find('\t', t2 + 1);
    out.type = (t1 == std::string::npos) ? s : s.substr(0, t1);
    out.usage = (t1 != std::string::npos && t2 != std::string::npos)
                    ? s.substr(t1 + 1, t2 - t1 - 1)
                    : "";
    out.threat = (t2 != std::string::npos && t3 != std::string::npos)
                     ? s.substr(t2 + 1, t3 - t2 - 1)
                     : "";
    return true;
  }

private:
  uint32_t u32(size_t off) const {
    return static_cast<uint32_t>(data_[off]) |
           (static_cast<uint32_t>(data_[off + 1]) << 8) |
           (static_cast<uint32_t>(data_[off + 2]) << 16) |
           (static_cast<uint32_t>(data_[off + 3]) << 24);
  }
  std::vector<uint8_t> data_;
  std::vector<std::string> strs_;
  size_t rows_ = 0;
  bool ready_ = false;
};
