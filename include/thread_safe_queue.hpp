#pragma once
#include <atomic>
#include <condition_variable>
#include <functional>
#include <iterator>
#include <map>
#include <mutex>
#include <optional>

// Bounded, thread-safe queue with optional priority ordering and an
// emergency-only drop policy.
//
//   push(item)            FIFO (priority 0) — backward compatible.
//   push(item, priority)  higher priority is popped first; equal priorities
//                         keep insertion order (FIFO within a priority band).
//
// Capacity behavior when the queue is full:
//   - Blocking mode (set_blocking(true), used for offline/forensic replay):
//     push() waits for space — nothing is lost.
//   - Non-blocking mode (live capture): the hard limit is reached, so the queue
//     performs an EMERGENCY drop. It evicts the LOWEST-priority queued item if
//     the incoming item outranks it; otherwise it drops the incoming item.
//     Either way the most-suspicious flows survive. Every drop is counted.
//
// See obsidian-vault/architecture/"Operating Modes (Live NIDS vs Forensic).md":
// hold by default, prioritize the scary ones, skip only as a last resort.
template <typename T> class ThreadSafeQueue {
private:
  // key = priority; std::greater makes begin() the highest priority. A multimap
  // preserves insertion order among equal keys, so equal priorities stay FIFO.
  std::multimap<int, T, std::greater<int>> q;
  std::mutex m;
  std::condition_variable cv;       // notifies pop() waiters
  std::condition_variable cv_push;  // notifies push() waiters (backpressure)
  bool done = false;
  bool blocking_ = false;
  size_t max_capacity;
  std::atomic<size_t> dropped_count{0};

public:
  explicit ThreadSafeQueue(size_t capacity = 1024) : max_capacity(capacity) {}

  // Enable/disable backpressure mode. When blocking, push() waits for space
  // instead of dropping. Disabling unblocks any waiting pushers.
  void set_blocking(bool enable) {
    std::lock_guard<std::mutex> lock(m);
    blocking_ = enable;
    if (!enable)
      cv_push.notify_all();
  }

  void push(T item, int priority = 0) {
    std::unique_lock<std::mutex> lock(m);
    if (q.size() >= max_capacity) {
      if (!blocking_) {
        // Emergency drop (live mode, hard limit reached): keep the most
        // suspicious. The lowest-priority queued item is the last element.
        auto lowest = std::prev(q.end());
        if (priority > lowest->first) {
          q.erase(lowest); // evict the least-suspicious queued flow
          dropped_count.fetch_add(1, std::memory_order_relaxed);
          q.emplace(priority, std::move(item));
          cv.notify_one();
        } else {
          // Incoming is no more suspicious than the weakest queued — drop it.
          dropped_count.fetch_add(1, std::memory_order_relaxed);
        }
        return;
      }
      // Backpressure: wait until space is available, or shutdown/unblock.
      cv_push.wait(lock, [this] {
        return q.size() < max_capacity || done || !blocking_;
      });
      if (q.size() >= max_capacity) {
        // Woke because done or blocking disabled — drop.
        dropped_count.fetch_add(1, std::memory_order_relaxed);
        return;
      }
    }
    q.emplace(priority, std::move(item));
    cv.notify_one();
  }

  std::optional<T> pop() {
    std::unique_lock<std::mutex> lock(m);
    cv.wait(lock, [this] { return !q.empty() || done; });
    if (q.empty() && done)
      return std::nullopt;
    auto it = q.begin(); // highest priority; FIFO within a priority band
    T item = std::move(it->second);
    q.erase(it);
    cv_push.notify_one(); // wake one blocked pusher
    return item;
  }

  void finish() {
    std::lock_guard<std::mutex> lock(m);
    done = true;
    cv.notify_all();
    cv_push.notify_all(); // unblock any waiting pushers
  }

  size_t size() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex &>(m));
    return q.size();
  }

  size_t get_dropped_count() const {
    return dropped_count.load(std::memory_order_relaxed);
  }

  size_t capacity() const { return max_capacity; }
};
