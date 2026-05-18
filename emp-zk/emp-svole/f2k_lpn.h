#ifndef EMP_SVOLE_F2K_LPN_H__
#define EMP_SVOLE_F2K_LPN_H__

#include "emp-tool/emp-tool.h"
#include <algorithm>
#include <functional>

// F2k LPN linear-code amplifier. SoA: separate K[] (val) and F[] (mac)
// arrays. Each output i accumulates `d` random pre[idx_j] entries via
// P::k_add (val) / P::f_add (mac). Sender (ALICE) folds both; receiver
// (BOB) folds only mac.

namespace emp {

template <typename P, int d = 10> class F2kLpnAmp {
public:
  using F = typename P::F;
  using K = typename P::K;

  int party;
  int64_t k, n;
  block seed;
  uint32_t k_mask;

  K *Val = nullptr, *preV = nullptr;       // preV: const, but legacy code passes non-const
  F *Mac = nullptr, *preM = nullptr;

  F2kLpnAmp(int64_t n, int64_t k, block seed = zero_block)
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
      Val[idx1] = P::k_add(Val[idx1], preV[idx2[j]]);
      Mac[idx1] = P::f_add(Mac[idx1], preM[idx2[j]]);
    }
  }

  // BOB: fold only mac.
  void add1(int64_t idx1, uint32_t *idx2) {
    for (int j = 0; j < d; ++j) {
      Mac[idx1] = P::f_add(Mac[idx1], preM[idx2[j]]);
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
          &F2kLpnAmp::add2, this, std::placeholders::_1,
          std::placeholders::_2);
      for (; j < n - 4; j += 4)
        __compute4(j, &prp, add_func1);
      for (; j < n; ++j)
        __compute1(j, &prp, add_func1);
    } else {
      std::function<void(int64_t, uint32_t *)> add_func2 = std::bind(
          &F2kLpnAmp::add1, this, std::placeholders::_1,
          std::placeholders::_2);
      for (; j < n - 4; j += 4)
        __compute4(j, &prp, add_func2);
      for (; j < n; ++j)
        __compute1(j, &prp, add_func2);
    }
  }

  void compute_send(K *preV_in, K *V, F *preM_in, F *M) {
    this->party = ALICE;
    this->preV = preV_in;
    this->Val = V;
    this->preM = preM_in;
    this->Mac = M;
    compute();
  }

  void compute_recv(F *preM_in, F *M) {
    this->party = BOB;
    this->preM = preM_in;
    this->Mac = M;
    compute();
  }
};

} // namespace emp
#endif
