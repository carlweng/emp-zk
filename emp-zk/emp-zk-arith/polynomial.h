#ifndef FP_POLY_H__
#define FP_POLY_H__

#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk-arith/ostriple.h"
#include "emp-zk/emp-zk-bool/emp-zk-bool.h"
#include <future>
#include <vector>

namespace emp {
using namespace std;

class FpPolyProof {
public:
  static FpPolyProof *fppolyproof;
  int party;
  BoolIO *io;
  uint64_t delta;
  int64_t buffer_sz = 1024;
  std::vector<uint64_t> buffer;
  std::vector<uint64_t> buffer1;
  FpOSTriple *ostriple;
  int64_t num;

  FpPolyProof(int party, BoolIO *io, FpOSTriple *ostriple) {
    this->party = party;
    this->io = io;
    this->ostriple = ostriple;
    buffer.resize(buffer_sz);
    if (party == ALICE) {
      buffer1.resize(buffer_sz);
    } else {
      this->delta = LOW64(ostriple->delta);
    }
    num = 0;
  }

  ~FpPolyProof() { batch_check(); }

  // Below this per-call length the loop is cheaper serial than the pool
  // dispatch; above it, split [0,n) across ostriple's worker pool.
  static constexpr int64_t kParMin = 64;

  // Parallel F_p sum of f(i) over [0,n), reusing FpOSTriple's ThreadPool.
  // Serial when single-threaded or below kParMin. Each worker accumulates a
  // private partial; partials are add_mod-combined (field add is associative).
  template <typename Fn>
  uint64_t par_sum_(int64_t n, Fn &&f) const {
    const int T = ostriple->threads_;
    ThreadPool *pool = ostriple->pool_;
    if (T <= 1 || pool == nullptr || n < kParMin) {
      uint64_t s = 0;
      for (int64_t i = 0; i < n; ++i) s = add_mod(s, f(i));
      return s;
    }
    std::vector<uint64_t> part((size_t)T, 0);
    const int64_t width = n / T;
    std::vector<std::future<void>> fut;
    for (int t = 0; t < T - 1; ++t) {
      const int64_t s = (int64_t)t * width, e = s + width;
      fut.push_back(pool->enqueue([&part, t, s, e, &f]() {
        uint64_t acc = 0;
        for (int64_t i = s; i < e; ++i) acc = add_mod(acc, f(i));
        part[(size_t)t] = acc;
      }));
    }
    uint64_t acc = 0;
    for (int64_t i = (int64_t)(T - 1) * width; i < n; ++i) acc = add_mod(acc, f(i));
    part[(size_t)(T - 1)] = acc;
    for (auto &fu : fut) fu.get();
    uint64_t r = 0;
    for (int t = 0; t < T; ++t) r = add_mod(r, part[(size_t)t]);
    return r;
  }

  void batch_check() {
    if (num == 0)
      return;
    uint64_t seed;
    io->flush();
    std::vector<uint64_t> chi(num);
    __uint128_t ope_data;
    uint64_t check_sum[2];
    if (party == ALICE) {
      io->recv_data(&seed, sizeof(uint64_t));

      uni_hash_coeff_gen(chi.data(), seed, num);

      check_sum[0] = vector_inn_prdt_sum_red(chi.data(), buffer.data(), num);
      check_sum[1] = vector_inn_prdt_sum_red(chi.data(), buffer1.data(), num);
      ostriple->draw_vole((AuthValueFp *)&ope_data, 1);

      check_sum[0] = add_mod(check_sum[0], MAC(ope_data));
      check_sum[1] = add_mod(check_sum[1], VAL(ope_data));
      io->send_data(check_sum, 2 * sizeof(uint64_t));
    } else {
      PRG prg;
      prg.random_data_unaligned(&seed, sizeof(uint64_t));
      seed = mod(seed);
      io->send_data(&seed, sizeof(uint64_t));

      uni_hash_coeff_gen(chi.data(), seed, num);
      uint64_t B = vector_inn_prdt_sum_red(chi.data(), buffer.data(), num);
      ostriple->draw_vole((AuthValueFp *)&ope_data, 1);
      B = add_mod(B, MAC(ope_data));
      io->recv_data(check_sum, 2 * sizeof(uint64_t));

      uint64_t tmp = mult_mod(check_sum[1], delta);
      tmp = add_mod(B, tmp);
      if (tmp != check_sum[0])
        error("polynomial zkp fails");
    }
    num = 0;
  }

  inline void zkp_poly_deg2(const __uint128_t *polyx, const __uint128_t *polyy,
                            const uint64_t *coeff, int64_t len) {
    if (num >= buffer_sz)
      batch_check();

    if (party == ALICE) {
      // A0 = Σ coeff[i+1]·(m0·m1);  A1 = Σ coeff[i+1]·(m0·w1 + m1·w0).
      uint64_t A0 = par_sum_(len, [&](int64_t i) {
        return mult_mod(coeff[i + 1], mult_mod(MAC(polyx[i]), MAC(polyy[i])));
      });
      uint64_t A1 = par_sum_(len, [&](int64_t i) {
        uint64_t t = add_mod(mult_mod(MAC(polyx[i]), VAL(polyy[i])),
                             mult_mod(MAC(polyy[i]), VAL(polyx[i])));
        return mult_mod(coeff[i + 1], t);
      });
      buffer[num] = A0;
      buffer1[num] = A1;
    } else {
      uint64_t B = par_sum_(len, [&](int64_t i) {
        return mult_mod(coeff[i + 1], mult_mod(MAC(polyx[i]), MAC(polyy[i])));
      });
      uint64_t tmp = mult_mod(delta, delta);
      tmp = mult_mod(coeff[0], tmp);
      B = add_mod(B, tmp);
      buffer[num] = B;
    }
    num++;
  }

  inline void zkp_inner_prdt(const __uint128_t *polyx, const __uint128_t *polyy,
                             uint64_t constant, int64_t len) {
    if (num >= buffer_sz)
      batch_check();

    if (party == ALICE) {
      // A0 = Σ m0·m1;  A1 = Σ (m0·w1 + m1·w0).
      uint64_t A0 = par_sum_(len, [&](int64_t i) {
        return mult_mod(MAC(polyx[i]), MAC(polyy[i]));
      });
      uint64_t A1 = par_sum_(len, [&](int64_t i) {
        return add_mod(mult_mod(MAC(polyx[i]), VAL(polyy[i])),
                       mult_mod(MAC(polyy[i]), VAL(polyx[i])));
      });
      buffer[num] = A0;
      buffer1[num] = A1;
    } else {
      uint64_t B = par_sum_(len, [&](int64_t i) {
        return mult_mod(MAC(polyx[i]), MAC(polyy[i]));
      });
      uint64_t tmp = mult_mod(delta, delta);
      tmp = mult_mod(constant, tmp);
      B = add_mod(B, tmp);
      buffer[num] = B;
    }
    num++;
  }
};
inline FpPolyProof *FpPolyProof::fppolyproof = nullptr;
}  // namespace emp

#endif
