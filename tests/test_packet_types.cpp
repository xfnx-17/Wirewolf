#include <catch2/catch_test_macros.hpp>
#include "packet_types.hpp"
#include <unordered_set>

TEST_CASE("ConnectionId equality", "[packet]") {
  ConnectionId a{0x0A000001, 0x0A000002, 80, 12345};
  ConnectionId b{0x0A000001, 0x0A000002, 80, 12345};
  ConnectionId c{0x0A000001, 0x0A000002, 80, 12346};

  REQUIRE(a == b);
  REQUIRE_FALSE(a == c);
}

TEST_CASE("ConnectionId hash consistency", "[packet]") {
  ConnectionId a{0x0A000001, 0x0A000002, 80, 12345};
  ConnectionId b{0x0A000001, 0x0A000002, 80, 12345};

  std::hash<ConnectionId> hasher;
  REQUIRE(hasher(a) == hasher(b));
}

TEST_CASE("ConnectionId hash uniqueness for different connections", "[packet]") {
  std::unordered_set<ConnectionId> set;

  set.insert({0x0A000001, 0x0A000002, 80, 1000});
  set.insert({0x0A000001, 0x0A000002, 80, 1001});
  set.insert({0x0A000001, 0x0A000002, 443, 1000});
  set.insert({0x0A000003, 0x0A000002, 80, 1000});

  REQUIRE(set.size() == 4);
}

TEST_CASE("ConnectionId hash works with unordered_map", "[packet]") {
  std::unordered_map<ConnectionId, int> map;
  ConnectionId cid{0xC0A80001, 0xC0A80002, 443, 50000};

  map[cid] = 42;
  REQUIRE(map.count(cid) == 1);
  REQUIRE(map[cid] == 42);

  ConnectionId cid2{0xC0A80001, 0xC0A80002, 443, 50001};
  REQUIRE(map.count(cid2) == 0);
}

TEST_CASE("FlowData default construction", "[packet]") {
  FlowData flow;
  REQUIRE(flow.reassembled_payload.empty());
  REQUIRE(flow.packet_count == 0);
}
