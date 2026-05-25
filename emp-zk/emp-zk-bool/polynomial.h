#ifndef POLY_H__
#define POLY_H__

#include "emp-ot/emp-ot.h"
#include "emp-tool/emp-tool.h"

// emp-tool no longer binds a default wire; emp-zk is a block-wire library.
EMP_USE_CIRCUIT_TYPES(block, Bit, SignedInt);

namespace emp {
using namespace std;

class PolyProof {
public:
  static constexpr int64_t buffer_sz = 1 << 20;

  int party;
  IOChannel *io;
  block delta;
  std::vector<block> buffer;  // ALICE: A0 (Δ⁰ coeff); BOB: full B = poly(Δ)
  std::vector<block> buffer1; // ALICE: A1 (Δ¹ coeff); BOB: unused
  int64_t num;
  GaloisFieldPacking pack;
  Ferret *ferret = nullptr;

  PolyProof(int party, IOChannel *io, Ferret *ferret)
      : party(party), io(io), delta(ferret->Delta), ferret(ferret), num(0) {
    buffer.resize(buffer_sz);
    if (party == ALICE)
      buffer1.resize(buffer_sz);
  }

  ~PolyProof() { batch_check(); }

  void batch_check() {
    if (num == 0)
      return;

    block seed;
    std::vector<block> chi(num > 4 ? num : 4);
    block ope_data[128];
    block check_sum[2];
    if (party == ALICE) {
      io->recv_data(&seed, sizeof(block));

      uni_hash_coeff_gen(chi.data(), seed, num > 4 ? num : 4);

      vector_inn_prdt_sum_red(check_sum, chi.data(), buffer.data(), num);
      vector_inn_prdt_sum_red(check_sum + 1, chi.data(), buffer1.data(), num);
      ferret->next_n(ope_data, 128);
      block tmp;
      pack.packing(&tmp, ope_data);
      uint64_t choice_bits[2];
      for (int i = 0; i < 2; ++i) {
        choice_bits[i] = 0;
        for (int64_t j = 63; j >= 0; --j) {
          choice_bits[i] <<= 1;
          if (getLSB(ope_data[i * 64 + j]))
            choice_bits[i] |= 0x1;
        }
      }
      check_sum[0] = check_sum[0] ^ tmp;
      tmp = makeBlock(choice_bits[1], choice_bits[0]);
      check_sum[1] = check_sum[1] ^ tmp;
      io->send_data(check_sum, 2 * sizeof(block));
      io->flush();
    } else {
      PRG prg;
      prg.random_block(&seed, 1);
      io->send_data(&seed, sizeof(block));
      io->flush();

      uni_hash_coeff_gen(chi.data(), seed, num > 4 ? num : 4);
      block B;
      vector_inn_prdt_sum_red(&B, chi.data(), buffer.data(), num);
      ferret->next_n(ope_data, 128);
      block tmp;
      pack.packing(&tmp, ope_data);

      B = B ^ tmp;
      io->recv_data(check_sum, 2 * sizeof(block));

      gfmul(check_sum[1], delta, &tmp);
      check_sum[1] = B ^ tmp;
      if (cmpBlock(check_sum, check_sum + 1, 1) != 1)
        error("zk polynomial: boolean polynomial zkp fails");
    }
    num = 0;
  }

  // Accumulators for one (a, b) pair into the per-call A0 / A1 (ALICE)
  // or B (BOB). Algebra:
  //   commitment(a)·commitment(b) = a·b + (a·b̃+b·ã)·Δ + ã·b̃·Δ²
  // ALICE collects the Δ⁰ term in A0 and the Δ¹ term in A1; BOB
  // evaluates the prover's polynomial at his secret Δ into B. Both
  // sides MAC into the LSB so getLSB(x) extracts the cleartext bit.
  inline void accumulate_alice(block a, block b, block &A0, block &A1) const {
    block t;
    gfmul(a, b, &t);
    A0 = A0 ^ t;
    A1 = A1 ^ (getLSB(b) ? a : zero_block) ^ (getLSB(a) ? b : zero_block);
  }
  inline void accumulate_bob(block a, block b, block &B) const {
    block t;
    gfmul(a, b, &t);
    B = B ^ t;
  }
  // Δ² masking term BOB xors in when a public constant bit is set.
  // Only zkp_poly_deg2 (coeff[0]) and zkp_inner_prdt (constant) use
  // it; the other variants pass false and pay nothing.
  inline block bob_constant_term(bool b) const {
    if (!b)
      return zero_block;
    block t;
    gfmul(delta, delta, &t);
    return t;
  }

  inline void zkp_poly_deg2(block *polyx, block *polyy, bool *coeff, int64_t len) {
    if (num >= buffer_sz)
      batch_check();
    if (party == ALICE) {
      block A0 = zero_block, A1 = zero_block;
      for (int64_t i = 0; i < len; ++i)
        if (coeff[i + 1])
          accumulate_alice(polyx[i], polyy[i], A0, A1);
      buffer[num] = A0;
      buffer1[num] = A1;
    } else {
      block B = zero_block;
      for (int64_t i = 0; i < len; ++i)
        if (coeff[i + 1])
          accumulate_bob(polyx[i], polyy[i], B);
      B = B ^ bob_constant_term(coeff[0]);
      buffer[num] = B;
    }
    num++;
  }

  inline void zkp_inner_prdt(block *polyx, block *polyy, bool constant,
                             int64_t len) {
    if (num >= buffer_sz)
      batch_check();
    if (party == ALICE) {
      block A0 = zero_block, A1 = zero_block;
      for (int64_t i = 0; i < len; ++i)
        accumulate_alice(polyx[i], polyy[i], A0, A1);
      buffer[num] = A0;
      buffer1[num] = A1;
    } else {
      block B = zero_block;
      for (int64_t i = 0; i < len; ++i)
        accumulate_bob(polyx[i], polyy[i], B);
      B = B ^ bob_constant_term(constant);
      buffer[num] = B;
    }
    num++;
  }

  inline void zkp_inner_prdt_eq(block *polyx, block *polyy, block *r, block *s,
                                int64_t len, int64_t len2) {
    if (num >= buffer_sz)
      batch_check();
    if (party == ALICE) {
      block A0 = zero_block, A1 = zero_block;
      for (int64_t i = 0; i < len; ++i)
        accumulate_alice(polyx[i], polyy[i], A0, A1);
      for (int64_t i = 0; i < len2; ++i)
        accumulate_alice(r[i], s[i], A0, A1);
      buffer[num] = A0;
      buffer1[num] = A1;
    } else {
      block B = zero_block;
      for (int64_t i = 0; i < len; ++i)
        accumulate_bob(polyx[i], polyy[i], B);
      for (int64_t i = 0; i < len2; ++i)
        accumulate_bob(r[i], s[i], B);
      buffer[num] = B;
    }
    num++;
  }

  inline void zkp_inner_prdt_eq(block *polyx, block *polyy, block *r, block *s,
                                block *rr, block *ss, int64_t len, int64_t len2) {
    if (num >= buffer_sz)
      batch_check();
    if (party == ALICE) {
      block A0 = zero_block, A1 = zero_block;
      for (int64_t i = 0; i < len; ++i)
        accumulate_alice(polyx[i], polyy[i], A0, A1);
      for (int64_t i = 0; i < len2; ++i)
        accumulate_alice(r[i], s[i], A0, A1);
      accumulate_alice(*rr, *ss, A0, A1);
      buffer[num] = A0;
      buffer1[num] = A1;
    } else {
      block B = zero_block;
      for (int64_t i = 0; i < len; ++i)
        accumulate_bob(polyx[i], polyy[i], B);
      for (int64_t i = 0; i < len2; ++i)
        accumulate_bob(r[i], s[i], B);
      accumulate_bob(*rr, *ss, B);
      buffer[num] = B;
    }
    num++;
  }

  inline void zkp_inner_prdt_multi(SignedInt *polyx, SignedInt *polyy, Bit *r,
                                   Bit *s, int64_t len, int64_t in_width) {
    for (int64_t width = 0; width < in_width; ++width) {
      if (num >= buffer_sz)
        batch_check();
      if (party == ALICE) {
        block A0 = zero_block, A1 = zero_block;
        for (int64_t i = 0; i < len; ++i)
          accumulate_alice(polyx[i][width].bit, polyy[0][i].bit, A0, A1);
        accumulate_alice(r[width].bit, s->bit, A0, A1);
        buffer[num] = A0;
        buffer1[num] = A1;
      } else {
        block B = zero_block;
        for (int64_t i = 0; i < len; ++i)
          accumulate_bob(polyx[i][width].bit, polyy[0][i].bit, B);
        accumulate_bob(r[width].bit, s->bit, B);
        buffer[num] = B;
      }
      num++;
    }
  }
};

} // namespace emp
#endif
