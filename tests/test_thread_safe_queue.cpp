#include <catch2/catch_test_macros.hpp>
#include "thread_safe_queue.hpp"
#include <thread>
#include <vector>

TEST_CASE("ThreadSafeQueue basic push/pop", "[queue]") {
  ThreadSafeQueue<int> q;

  q.push(42);
  auto val = q.pop();
  REQUIRE(val.has_value());
  REQUIRE(val.value() == 42);
}

TEST_CASE("ThreadSafeQueue respects FIFO order", "[queue]") {
  ThreadSafeQueue<int> q;

  q.push(1);
  q.push(2);
  q.push(3);

  REQUIRE(q.pop().value() == 1);
  REQUIRE(q.pop().value() == 2);
  REQUIRE(q.pop().value() == 3);
}

TEST_CASE("ThreadSafeQueue returns nullopt when finished and empty", "[queue]") {
  ThreadSafeQueue<int> q;

  q.push(10);
  q.finish();

  auto val = q.pop();
  REQUIRE(val.has_value());
  REQUIRE(val.value() == 10);

  auto empty = q.pop();
  REQUIRE_FALSE(empty.has_value());
}

TEST_CASE("ThreadSafeQueue drops items at capacity", "[queue]") {
  ThreadSafeQueue<int> q(3);

  q.push(1);
  q.push(2);
  q.push(3);
  q.push(4); // Should be dropped

  REQUIRE(q.size() == 3);
  REQUIRE(q.get_dropped_count() == 1);

  REQUIRE(q.pop().value() == 1);
  REQUIRE(q.pop().value() == 2);
  REQUIRE(q.pop().value() == 3);
}

TEST_CASE("ThreadSafeQueue tracks multiple drops", "[queue]") {
  ThreadSafeQueue<int> q(2);

  q.push(1);
  q.push(2);
  q.push(3); // drop
  q.push(4); // drop
  q.push(5); // drop

  REQUIRE(q.get_dropped_count() == 3);
  REQUIRE(q.size() == 2);
}

TEST_CASE("ThreadSafeQueue custom capacity", "[queue]") {
  ThreadSafeQueue<int> q(5);
  REQUIRE(q.capacity() == 5);
}

TEST_CASE("ThreadSafeQueue default capacity is 1024", "[queue]") {
  ThreadSafeQueue<int> q;
  REQUIRE(q.capacity() == 1024);
}

TEST_CASE("ThreadSafeQueue producer-consumer across threads", "[queue]") {
  ThreadSafeQueue<int> q;
  std::vector<int> results;
  const int count = 100;

  std::thread producer([&]() {
    for (int i = 0; i < count; i++) {
      q.push(i);
    }
    q.finish();
  });

  std::thread consumer([&]() {
    while (true) {
      auto val = q.pop();
      if (!val.has_value())
        break;
      results.push_back(val.value());
    }
  });

  producer.join();
  consumer.join();

  REQUIRE(results.size() == count);
  for (int i = 0; i < count; i++) {
    REQUIRE(results[i] == i);
  }
}

TEST_CASE("ThreadSafeQueue finish unblocks waiting consumer", "[queue]") {
  ThreadSafeQueue<int> q;
  bool consumer_done = false;

  std::thread consumer([&]() {
    auto val = q.pop(); // Will block until finish()
    REQUIRE_FALSE(val.has_value());
    consumer_done = true;
  });

  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  REQUIRE_FALSE(consumer_done);

  q.finish();
  consumer.join();

  REQUIRE(consumer_done);
}

// ── Backpressure (blocking mode) tests ──────────────────────────────

TEST_CASE("ThreadSafeQueue blocking mode waits instead of dropping", "[queue]") {
  ThreadSafeQueue<int> q(3);
  q.set_blocking(true);

  q.push(1);
  q.push(2);
  q.push(3);
  // Queue is now full. Next push would block.
  // Launch a thread that pushes (will block) then a consumer that pops.
  std::atomic<bool> push_done{false};

  std::thread producer([&]() {
    q.push(4); // Should block until consumer pops
    push_done = true;
  });

  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  REQUIRE_FALSE(push_done); // Still blocked

  // Pop one item to make space
  auto val = q.pop();
  REQUIRE(val.value() == 1);

  producer.join();
  REQUIRE(push_done);

  // Item 4 should now be in the queue
  REQUIRE(q.pop().value() == 2);
  REQUIRE(q.pop().value() == 3);
  REQUIRE(q.pop().value() == 4);
  REQUIRE(q.get_dropped_count() == 0);
}

TEST_CASE("ThreadSafeQueue blocking mode zero drops under pressure", "[queue]") {
  ThreadSafeQueue<int> q(2);
  q.set_blocking(true);

  const int count = 50;
  std::vector<int> results;

  std::thread producer([&]() {
    for (int i = 0; i < count; i++) {
      q.push(i);
    }
    q.finish();
  });

  std::thread consumer([&]() {
    while (true) {
      auto val = q.pop();
      if (!val.has_value())
        break;
      results.push_back(val.value());
    }
  });

  producer.join();
  consumer.join();

  REQUIRE(results.size() == count);
  REQUIRE(q.get_dropped_count() == 0);
  for (int i = 0; i < count; i++) {
    REQUIRE(results[i] == i);
  }
}

TEST_CASE("ThreadSafeQueue set_blocking(false) unblocks waiting pushers", "[queue]") {
  ThreadSafeQueue<int> q(2);
  q.set_blocking(true);

  q.push(1);
  q.push(2);
  // Queue full. Next push blocks.

  std::atomic<bool> push_done{false};
  std::thread producer([&]() {
    q.push(3); // Will block
    push_done = true;
  });

  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  REQUIRE_FALSE(push_done);

  // Disable blocking — pusher should unblock and drop
  q.set_blocking(false);
  producer.join();
  REQUIRE(push_done);
  REQUIRE(q.get_dropped_count() == 1); // item 3 was dropped
  REQUIRE(q.size() == 2);              // original 2 items remain
}

TEST_CASE("ThreadSafeQueue finish unblocks blocked pushers", "[queue]") {
  ThreadSafeQueue<int> q(1);
  q.set_blocking(true);

  q.push(1); // fills queue

  std::atomic<bool> push_done{false};
  std::thread producer([&]() {
    q.push(2); // Will block
    push_done = true;
  });

  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  REQUIRE_FALSE(push_done);

  q.finish(); // Should unblock the pusher
  producer.join();
  REQUIRE(push_done);
}

TEST_CASE("ThreadSafeQueue blocking mode can be toggled", "[queue]") {
  ThreadSafeQueue<int> q(2);

  // Start non-blocking (default)
  q.push(1);
  q.push(2);
  q.push(3); // dropped
  REQUIRE(q.get_dropped_count() == 1);

  q.pop(); // make space

  // Switch to blocking
  q.set_blocking(true);
  q.push(4); // should succeed (space available)
  REQUIRE(q.size() == 2);

  // Switch back to non-blocking
  q.set_blocking(false);
  q.push(5); // should drop (full)
  REQUIRE(q.get_dropped_count() == 2);
}
