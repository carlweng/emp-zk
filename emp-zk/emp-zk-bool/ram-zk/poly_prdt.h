#ifndef EMP_ZK_RAM_POLY_PRDT_H__
#define EMP_ZK_RAM_POLY_PRDT_H__

#include "emp-ot/emp-ot.h"

namespace emp {
using namespace std;

template <typename IO> class RamPolyPrdt {
public:
  int party;
  IO *io;
  block delta[4];
  int64_t buffer_sz = 1 << 20;
  std::vector<block> buffer0;
  std::vector<block> buffer1;
  std::vector<block> buffer2;
  std::vector<block> buffer3;
  std::vector<block> buffer4;
  Ferret *ferret = nullptr;
  int64_t num;

  RamPolyPrdt(int party, IO *io, Ferret *ferret)
      : party(party), io(io), ferret(ferret) {
    if (party == ALICE) {
      buffer0.resize(buffer_sz);
      buffer1.resize(buffer_sz);
      buffer2.resize(buffer_sz);
      buffer3.resize(buffer_sz);
      buffer4.resize(buffer_sz);
    } else {
      buffer0.resize(buffer_sz);
      delta[0] = ferret->Delta;
      gfmul(delta[0], delta[0], delta + 1);
      gfmul(delta[1], delta[0], delta + 2);
      gfmul(delta[2], delta[0], delta + 3);
    }
    num = 0;
  }

  ~RamPolyPrdt() { batch_check(); }

  void batch_check() {
    if (num == 0)
      return;
    io->flush();
    std::vector<block> chi(num);
    block check_sum[5];
    if (party == ALICE) {
      block seed = io->get_hash_block();
      uni_hash_coeff_gen(chi.data(), seed, num);

      vector_inn_prdt_sum_red(check_sum,     chi.data(), buffer0.data(), num);
      vector_inn_prdt_sum_red(check_sum + 1, chi.data(), buffer1.data(), num);
      vector_inn_prdt_sum_red(check_sum + 2, chi.data(), buffer2.data(), num);
      vector_inn_prdt_sum_red(check_sum + 3, chi.data(), buffer3.data(), num);
      vector_inn_prdt_sum_red(check_sum + 4, chi.data(), buffer4.data(), num);

      // TODO mask
      //
      io->send_data(check_sum, 5 * sizeof(block));
      io->flush();
    } else {
      block seed = io->get_hash_block();
      uni_hash_coeff_gen(chi.data(), seed, num);

      block B;
      vector_inn_prdt_sum_red(&B, chi.data(), buffer0.data(), num);

      // TODO mask
      //
      io->recv_data(check_sum, 5 * sizeof(block));

      block t[4];
      for (int i = 0; i < 4; ++i)
        gfmul(check_sum[i + 1], delta[i], &t[i]);
      check_sum[0] ^= (t[0] ^ t[1] ^ t[2] ^ t[3]);
      if (memcmp(&B, check_sum, 16) != 0)
        error("product by polynomial fails");
    }
    num = 0;
  }

  // Templated polynomial-product MAC step.
  //
  // x[0..N-1], m[0..N-1] are the prover's (cleartext, MAC) pairs for N
  // committed values; m_last is the MAC the prover commits as the
  // product. Both sides build coefficients of the polynomial-in-Δ
  //
  //     P(Δ) = (k_1 + x_1 Δ)(k_2 + x_2 Δ) … (k_N + x_N Δ)
  //
  // (with k_i ≡ m_i in this code's spelling). The Δ^N coefficient is
  // x_1·x_2·…·x_N (the cleartext product, available to the caller as
  // `v`); we buffer the lower coefficients 0..N-1. The Δ^(N-1) slot
  // also folds in the m_last correction term so that
  //   buffer_{N-1} − m_last = coefficient of Δ^(N-1).
  // Higher-index buffers (N..4) are zeroed so batch_check's later
  // chi-fold sees a clean degree-N polynomial regardless of N.
  //
  // ALICE expands the polynomial iteratively
  //   poly_{i+1}[j] = poly_i[j] · k_{i+1} + poly_i[j-1] · x_{i+1}.
  // BOB stores only B = ⊓_i m_i + m_last · Δ^(N-1) in buffer0.
  template <int N>
  inline void polyPrdtN(const block *x, const block *m, const block &m_last) {
    static_assert(N >= 3 && N <= 5);
    if (num >= buffer_sz) batch_check();

    if (party == ALICE) {
      block poly[N + 1] = {};
      block tmp;

      // Hand-expand the 2-term init: poly = (k_1 + x_1 Δ)(k_2 + x_2 Δ).
      gfmul(m[0], m[1], &poly[0]);
      gfmul(m[0], x[1], &poly[1]);
      gfmul(x[0], m[1], &tmp);
      poly[1] ^= tmp;
      gfmul(x[0], x[1], &poly[2]);

      // Iteratively multiply in (k_i + x_i Δ) for i = 2 .. N-1.
      for (int i = 2; i < N; ++i) {
        block new_poly[N + 1] = {};
        // At the LAST step (i == N-1) the new top coefficient
        // new_poly[N] = poly[N-1] · x_i would be the all-x term =
        // x_1·…·x_N = v, which the caller already has; skip it.
        const int top = (i == N - 1) ? (N - 1) : (i + 1);
        for (int j = 0; j <= top; ++j) {
          if (j <= i)
            gfmul(poly[j], m[i], &new_poly[j]);
          if (j >= 1) {
            gfmul(poly[j - 1], x[i], &tmp);
            new_poly[j] ^= tmp;
          }
        }
        for (int j = 0; j <= top; ++j) poly[j] = new_poly[j];
      }

      // Coefficient layout: poly[0..N-1] → buffer0..buffer(N-1), with
      // buffer(N-1) folding in m_last; buffer(N..4) zeroed.
      block out[5];
      for (int j = 0; j < N - 1; ++j) out[j] = poly[j];
      out[N - 1] = poly[N - 1] ^ m_last;
      for (int j = N; j < 5; ++j) out[j] = zero_block;
      buffer0[num] = out[0];
      buffer1[num] = out[1];
      buffer2[num] = out[2];
      buffer3[num] = out[3];
      buffer4[num] = out[4];
    } else {
      block prod = m[0];
      for (int i = 1; i < N; ++i) gfmul(prod, m[i], &prod);
      // delta[k] = Δ^(k+1) (delta[0]=Δ, delta[1]=Δ², …);
      // delta[N-2] = Δ^(N-1).
      block adj;
      gfmul(m_last, delta[N - 2], &adj);
      buffer0[num] = prod ^ adj;
    }
    num++;
  }
};
}  // namespace emp

#endif
