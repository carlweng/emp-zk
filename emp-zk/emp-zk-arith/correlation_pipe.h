#ifndef CORRELATION_PIPE_H__
#define CORRELATION_PIPE_H__

#include <condition_variable>
#include <mutex>
#include <vector>

namespace emp {

// Bounded single-producer / single-consumer ring of correlation batches, used
// to hand sVOLE correlations from a background producer thread (running the
// sVOLE on its own socket) to the main consumer thread (the ZK engine). The
// producer blocks when the ring is full; the consumer blocks when it is empty.
// `finish()` wakes both so neither deadlocks at shutdown.
template <class T>
struct CorrelationPipe {
  std::vector<std::vector<T>> slot;
  const int N;
  const int64_t batch;
  std::mutex m;
  std::condition_variable cv_free, cv_ready;
  int head = 0, tail = 0, count = 0;
  bool done = false;
  bool producer_done = false;   // set by producer after it emits its last slot

  CorrelationPipe(int n, int64_t b) : slot(n), N(n), batch(b) {
    for (auto &s : slot) s.resize((size_t)b);
  }

  // Producer: index of a FREE slot to fill (blocks while full); -1 on shutdown.
  int acquire_free() {
    std::unique_lock<std::mutex> lk(m);
    cv_free.wait(lk, [&] { return count < N || done; });
    return done ? -1 : tail;
  }
  void publish() {
    { std::lock_guard<std::mutex> lk(m); tail = (tail + 1) % N; ++count; }
    cv_ready.notify_one();
  }
  void mark_producer_done() {
    { std::lock_guard<std::mutex> lk(m); producer_done = true; }
    cv_ready.notify_all();
  }

  // Consumer: index of a READY slot (blocks while empty). Returns -1 only when
  // the producer has finished AND the ring is drained (i.e. genuinely no more).
  int acquire_ready() {
    std::unique_lock<std::mutex> lk(m);
    cv_ready.wait(lk, [&] { return count > 0 || producer_done || done; });
    return count > 0 ? head : -1;
  }
  void release() {
    { std::lock_guard<std::mutex> lk(m); head = (head + 1) % N; --count; }
    cv_free.notify_one();
  }
  void finish() {
    { std::lock_guard<std::mutex> lk(m); done = true; }
    cv_free.notify_all();
    cv_ready.notify_all();
  }
};

}  // namespace emp

#endif
