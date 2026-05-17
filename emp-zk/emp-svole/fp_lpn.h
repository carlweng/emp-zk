#ifndef EMP_SVOLE_FP_LPN_H__
#define EMP_SVOLE_FP_LPN_H__

#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-svole/fp_utility.h"

// F_p LPN linear-code amplifier. Same shape as char-2 LpnAmplifier
// (PRP-seeded random d-subset indices per output, XOR-fold over the
// preV/preM pre-images), but the fold uses mod-p addition with SIMD
// SSE pairs to keep throughput comparable. d hard-coded to 10 with
// the 5+5 split that controls partial-mod frequency.
//
// Single-threaded (the call site in VoleTriple → SVole<FpPolicy> is
// single-threaded; the old ThreadPool dispatch is gone).

namespace emp {

template <int d = 10> class LpnFp {
public:
  int party;
  int64_t k, n;
  block seed;

  __uint128_t *M;
  const __uint128_t *preM, *prex;
  __uint128_t *K;
  const __uint128_t *preK;

  uint32_t k_mask;

  LpnFp(int64_t n, int64_t k, block seed = zero_block)
      : k(k), n(n), seed(seed) {
    k_mask = 1;
    while (k_mask < (uint32_t)k) {
      k_mask <<= 1;
      k_mask = k_mask | 0x1;
    }
  }

  void add2_single(int64_t idx1, int *idx2) {
    block Midx1 = (block)M[idx1];
    for (int j = 0; j < 5; ++j)
      Midx1 = _mm_add_epi64(Midx1, (block)preM[idx2[j]]);
    Midx1 = vec_mod(Midx1);
    for (int j = 5; j < 10; ++j)
      Midx1 = _mm_add_epi64(Midx1, (block)preM[idx2[j]]);
    M[idx1] = (__uint128_t)vec_mod(Midx1);
  }
  void add1_single(int64_t idx1, int *idx2) {
    uint64_t Kidx1 = K[idx1];
    for (int j = 0; j < 5; ++j)
      Kidx1 = Kidx1 + preK[idx2[j]];
    Kidx1 = mod(Kidx1);
    for (int j = 5; j < 10; ++j)
      Kidx1 = Kidx1 + preK[idx2[j]];
    K[idx1] = mod(Kidx1);
  }

  void add2(int64_t idx1, int *idx2) {
    block tmp[4];
    tmp[0] = (block)M[idx1];
    tmp[1] = (block)M[idx1 + 1];
    tmp[2] = (block)M[idx1 + 2];
    tmp[3] = (block)M[idx1 + 3];
    int *p = idx2;
    for (int j = 0; j < 5; ++j) {
      tmp[0] = _mm_add_epi64((block)tmp[0], (block)preM[*(p++)]);
      tmp[1] = _mm_add_epi64((block)tmp[1], (block)preM[*(p++)]);
      tmp[2] = _mm_add_epi64((block)tmp[2], (block)preM[*(p++)]);
      tmp[3] = _mm_add_epi64((block)tmp[3], (block)preM[*(p++)]);
    }
    tmp[0] = vec_mod(tmp[0]);
    tmp[1] = vec_mod(tmp[1]);
    tmp[2] = vec_mod(tmp[2]);
    tmp[3] = vec_mod(tmp[3]);
    for (int j = 5; j < 10; ++j) {
      tmp[0] = _mm_add_epi64((block)tmp[0], (block)preM[*(p++)]);
      tmp[1] = _mm_add_epi64((block)tmp[1], (block)preM[*(p++)]);
      tmp[2] = _mm_add_epi64((block)tmp[2], (block)preM[*(p++)]);
      tmp[3] = _mm_add_epi64((block)tmp[3], (block)preM[*(p++)]);
    }
    M[idx1] = (__uint128_t)vec_mod(tmp[0]);
    M[idx1 + 1] = (__uint128_t)vec_mod(tmp[1]);
    M[idx1 + 2] = (__uint128_t)vec_mod(tmp[2]);
    M[idx1 + 3] = (__uint128_t)vec_mod(tmp[3]);
  }

  void add1(int64_t idx1, int *idx2) {
    uint64_t tmp[4];
    tmp[0] = 0;
    tmp[1] = 0;
    tmp[2] = 0;
    tmp[3] = 0;
    int *p = idx2;
    for (int j = 0; j < 5; ++j) {
      tmp[0] += preK[*(p++)];
      tmp[1] += preK[*(p++)];
      tmp[2] += preK[*(p++)];
      tmp[3] += preK[*(p++)];
    }
    tmp[0] = mod(tmp[0]);
    tmp[1] = mod(tmp[1]);
    tmp[2] = mod(tmp[2]);
    tmp[3] = mod(tmp[3]);
    for (int j = 5; j < 10; ++j) {
      tmp[0] += preK[*(p++)];
      tmp[1] += preK[*(p++)];
      tmp[2] += preK[*(p++)];
      tmp[3] += preK[*(p++)];
    }
    K[idx1] = mod(K[idx1] + tmp[0]);
    K[idx1 + 1] = mod(K[idx1 + 1] + tmp[1]);
    K[idx1 + 2] = mod(K[idx1 + 2] + tmp[2]);
    K[idx1 + 3] = mod(K[idx1 + 3] + tmp[3]);
  }

  void __compute4(int64_t i, PRP *prp, std::function<void(int64_t, int *)> add_func) {
    block tmp[10];
    for (int m = 0; m < 10; ++m)
      tmp[m] = makeBlock(i, m);
    prp->permute_block(tmp, 10);
    int *index = (int *)(tmp);
    for (int j = 0; j < 4 * d; ++j) {
      index[j] = index[j] & k_mask;
      index[j] = index[j] >= k ? index[j] - k : index[j];
    }
    add_func(i, index);
  }

  void __compute1(int64_t i, PRP *prp, std::function<void(int64_t, int *)> add_func) {
    block tmp[3];
    for (int m = 0; m < 3; ++m)
      tmp[m] = makeBlock(i, m);
    prp->permute_block(tmp, 3);
    uint32_t *r = (uint32_t *)(tmp);
    int index[d];
    for (int j = 0; j < d; ++j) {
      index[j] = r[j] & k_mask;
      index[j] = index[j] >= k ? index[j] - k : index[j];
    }
    add_func(i, index);
  }

  void compute() {
    PRP prp(seed);
    int64_t j = 0;
    if (party == ALICE) {
      std::function<void(int64_t, int *)> add_func1 = std::bind(
          &LpnFp::add1, this, std::placeholders::_1, std::placeholders::_2);
      std::function<void(int64_t, int *)> add_func1s =
          std::bind(&LpnFp::add1_single, this, std::placeholders::_1,
                    std::placeholders::_2);
      for (; j < n - 4; j += 4)
        __compute4(j, &prp, add_func1);
      for (; j < n; ++j)
        __compute1(j, &prp, add_func1s);
    } else {
      std::function<void(int64_t, int *)> add_func2 = std::bind(
          &LpnFp::add2, this, std::placeholders::_1, std::placeholders::_2);
      std::function<void(int64_t, int *)> add_func2s =
          std::bind(&LpnFp::add2_single, this, std::placeholders::_1,
                    std::placeholders::_2);
      for (; j < n - 4; j += 4)
        __compute4(j, &prp, add_func2);
      for (; j < n; ++j)
        __compute1(j, &prp, add_func2s);
    }
  }

  // AuthValue<FpPolicy>* aliases __uint128_t* (mac-first layout): the
  // public signatures take the typed form, internals reinterpret for
  // the SIMD pair adds.
  void compute_send(AuthValue<FpPolicy> *K_auth,
                    const AuthValue<FpPolicy> *kkK_auth) {
    this->party = ALICE;
    this->K = (__uint128_t *)K_auth;
    this->preK = (const __uint128_t *)kkK_auth;
    compute();
  }

  void compute_recv(AuthValue<FpPolicy> *M_auth,
                    const AuthValue<FpPolicy> *kkM_auth) {
    this->party = BOB;
    this->M = (__uint128_t *)M_auth;
    this->preM = (const __uint128_t *)kkM_auth;
    compute();
  }
};

} // namespace emp
#endif
