#ifndef EMP_SVOLE_LPN_AMP_H__
#define EMP_SVOLE_LPN_AMP_H__

#include "emp-zk/emp-svole/field_policy.h"
#include "emp-tool/emp-tool.h"
#include <algorithm>

// LPN linear-code amplifier over AuthValue<P>[]. Each output i
// accumulates `d` random pre[idx_j] entries via P::k_add / P::f_add.
// Sender (ALICE) folds both .val and .mac; receiver (BOB) only .mac.
// PRP-seeded index sampling identical to the original char-2 path.

namespace emp {

template <typename P, int d = 10> class LpnAmplifier {
public:
  using F = typename P::F;
  using K = typename P::K;
  using AV = AuthValue<P>;

  int party;
  int64_t k, n;
  block seed;
  uint32_t k_mask;

  AV *out_buf = nullptr;
  const AV *pre_buf = nullptr;

  LpnAmplifier(int64_t n, int64_t k, block seed = zero_block)
      : k(k), n(n), seed(seed) {
    k_mask = 1;
    while (k_mask < (uint32_t)k) {
      k_mask <<= 1;
      k_mask = k_mask | 0x1;
    }
  }

  // ALICE: fold val + mac.
  void add2(int64_t idx1, uint32_t *idx2) {
    for (int j = 0; j < d; ++j) {
      out_buf[idx1].val = P::k_add(out_buf[idx1].val, pre_buf[idx2[j]].val);
      out_buf[idx1].mac = P::f_add(out_buf[idx1].mac, pre_buf[idx2[j]].mac);
    }
  }

  // BOB: fold only mac.
  void add1(int64_t idx1, uint32_t *idx2) {
    for (int j = 0; j < d; ++j) {
      out_buf[idx1].mac = P::f_add(out_buf[idx1].mac, pre_buf[idx2[j]].mac);
    }
  }

  void __compute4(int64_t i, PRP *prp,
                  std::function<void(int64_t, uint32_t *)> add_func) {
    block tmp[10];
    for (int m = 0; m < 10; ++m)
      tmp[m] = makeBlock(i, m);
    prp->permute_block(tmp, 10);
    uint32_t *r = (uint32_t *)(tmp);
    for (int j = 0; j < 4 * d; ++j) {
      r[j] = r[j] & k_mask;
      r[j] = r[j] >= (uint32_t)k ? r[j] - k : r[j];
    }
    for (int m = 0; m < 4; ++m) {
      add_func(i + m, r + m * d);
    }
  }

  void __compute1(int64_t i, PRP *prp,
                  std::function<void(int64_t, uint32_t *)> add_func) {
    block tmp[3];
    for (int m = 0; m < 3; ++m)
      tmp[m] = makeBlock(i, m);
    prp->permute_block(tmp, 3);
    uint32_t *r = (uint32_t *)(tmp);
    for (int j = 0; j < d; ++j) {
      r[j] = r[j] & k_mask;
      r[j] = r[j] >= (uint32_t)k ? r[j] - k : r[j];
    }
    add_func(i, r);
  }

  void compute() {
    PRP prp(seed);
    int64_t j = 0;
    if (party == ALICE) {
      std::function<void(int64_t, uint32_t *)> add_func1 = std::bind(
          &LpnAmplifier::add2, this, std::placeholders::_1,
          std::placeholders::_2);
      for (; j < n - 4; j += 4)
        __compute4(j, &prp, add_func1);
      for (; j < n; ++j)
        __compute1(j, &prp, add_func1);
    } else {
      std::function<void(int64_t, uint32_t *)> add_func2 = std::bind(
          &LpnAmplifier::add1, this, std::placeholders::_1,
          std::placeholders::_2);
      for (; j < n - 4; j += 4)
        __compute4(j, &prp, add_func2);
      for (; j < n; ++j)
        __compute1(j, &prp, add_func2);
    }
  }

  void compute_send(const AV *pre, AV *out) {
    this->party = ALICE;
    this->pre_buf = pre;
    this->out_buf = out;
    compute();
  }

  void compute_recv(const AV *pre, AV *out) {
    this->party = BOB;
    this->pre_buf = pre;
    this->out_buf = out;
    compute();
  }
};

} // namespace emp
#endif
