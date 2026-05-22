#ifndef EMP_ZK_PERM_PROOF_H__
#define EMP_ZK_PERM_PROOF_H__

#include "emp-zk/emp-zk-bool/zk_bool_base.h"

namespace emp {
using namespace std;

// Zero-knowledge multiset permutation check over authenticated elements —
// the core gadget for VOLE-ZK RAM/ROM (Yang–Heath, "Two Shuffles Make a
// RAM", §2.2). The prover commits two multisets A and B; the proof passes
// iff A is a permutation of B.
//
// Method: encode each multiset as a polynomial with its elements as roots,
//   p_A(X) = ∏_i (X − a_i),   p_B(X) = ∏_i (X − b_i),
// and test p_A = p_B at a public-coin challenge r by Schwartz–Zippel. Both
// products are evaluated in zero knowledge as a chain of authenticated f2k
// multiplications (batched through f2k_mul_poly — the QuickSilver high-fan-in
// trick — so most factors cost no fresh VOLE); the two product wires are then
// opened and compared.
//
// Payload size (bits) is fixed at construction. ≤128 bits → each element is
// one F(2^128) wire and the product runs directly. Larger → an element spans
// m = ⌈bits/128⌉ wires that are *compressed* to one wire by the random linear
// combination Σ_j c_j·B_j with a public-coin coefficient vector c (a local
// op — f2k_mul_const / f2k_add — no VOLE, no comms). Distinct tuples collide
// under a random c only with prob ≈ 1/2^128, after which the single-wire
// product applies. Total soundness ≈ (|A| + m)/2^128.
//
// Compression is decoupled from the final check: add_* buffers raw (multi-
// wire) elements; compress() folds the current buffer into the compressed
// lists; the equality test (check_eq) runs once at the end. Each compress()
// draws a FRESH coefficient by Fiat–Shamir *at compress time* — bound to the
// transcript, so the just-committed elements being folded are bound (this is
// what makes it sound). Consequently elements folded in different compress()
// calls collapse under different coefficients and are NOT comparable across
// calls: every element that must match another in this permutation has to be
// folded in the same compress() call. The default flow (let check_eq() fold
// everything once, at the end) satisfies this for a whole-stream check.
class ZKPermProof {
public:
  ZKBoolBase *bb;
  int64_t n_blocks;   // wires per element = ⌈bits/128⌉

  // Pending raw elements (n_blocks wires each), awaiting compression. For
  // n_blocks == 1 add_* writes straight to the compressed lists and these
  // stay empty.
  std::vector<F2kAuthValue> a_pending, b_pending;
  // Collapsed single-wire elements; the permutation product runs over these.
  std::vector<F2kAuthValue> a_elems_compressed, b_elems_compressed;

  explicit ZKPermProof(int64_t payload_bits = 128)
      : bb(get_bool_backend()), n_blocks((payload_bits + 127) / 128) {}

  // Append one element. The pointer form reads n_blocks consecutive wires;
  // the reference form is a convenience for single-wire payloads (≤128 bits).
  void add_A(const F2kAuthValue *e) {
    if (n_blocks == 1) a_elems_compressed.push_back(*e);
    else a_pending.insert(a_pending.end(), e, e + n_blocks);
  }
  void add_B(const F2kAuthValue *e) {
    if (n_blocks == 1) b_elems_compressed.push_back(*e);
    else b_pending.insert(b_pending.end(), e, e + n_blocks);
  }
  void add_A(const F2kAuthValue &e) { add_A(&e); }   // requires n_blocks == 1
  void add_B(const F2kAuthValue &e) { add_B(&e); }   // requires n_blocks == 1

  // Fold the pending multi-wire elements into the compressed lists, drawing a
  // fresh coefficient vector by Fiat–Shamir now (so it binds the committed
  // elements being folded). No-op for single-wire payloads or an empty
  // buffer. Matched elements must be folded in the same call (see class doc).
  void compress() {
    if (n_blocks == 1 || (a_pending.empty() && b_pending.empty())) return;
    bb->io->flush();
    block seed = bb->io->get_hash_block();
    std::vector<block> coeff(n_blocks);
    PRG(&seed).random_block(coeff.data(), (int)n_blocks);
    fold_(a_pending, coeff.data(), a_elems_compressed);
    fold_(b_pending, coeff.data(), b_elems_compressed);
    a_pending.clear();
    b_pending.clear();
  }

  // Prove A ∼ B. Folds any remaining elements, then runs the product test at
  // a fresh challenge r. On the verifier this aborts (error()) on failure.
  // Resets state so the object can be reused.
  void check_eq() {
    compress();
    if (a_elems_compressed.size() != b_elems_compressed.size())
      error("ZKPermProof: |A| != |B|");
    if (!a_elems_compressed.empty()) {
      bb->io->flush();
      // Domain-separated from any compress() coefficient seed so r stays
      // independent even when the last fold and this draw share a transcript
      // point (compress() is local — it does no IO).
      block seed = bb->io->get_hash_block() ^ makeBlock(0, 1);
      block r;
      PRG(&seed).random_block(&r, 1);
      F2kAuthValue pa = eval_(a_elems_compressed, r);
      F2kAuthValue pb = eval_(b_elems_compressed, r);
      open_eq_(pa, pb);
    }
    a_pending.clear();
    b_pending.clear();
    a_elems_compressed.clear();
    b_elems_compressed.clear();
  }

private:
  // Collapse each m-wire element to one: out_i = Σ_j coeff_j · elem_i[j].
  // Public coeffs ⇒ all local (f2k_mul_const + f2k_add), no VOLE/comms.
  void fold_(const std::vector<F2kAuthValue> &flat, const block *coeff,
             std::vector<F2kAuthValue> &out) {
    const int64_t cnt = (int64_t)flat.size() / n_blocks;
    for (int64_t i = 0; i < cnt; ++i) {
      const F2kAuthValue *e = &flat[i * n_blocks];
      F2kAuthValue acc = bb->f2k_mul_const(e[0], coeff[0]);
      for (int64_t j = 1; j < n_blocks; ++j)
        acc = bb->f2k_add(acc, bb->f2k_mul_const(e[j], coeff[j]));
      out.push_back(acc);
    }
  }

  // ∏_i (r − elem_i) over the authenticated wires (r is a public constant; in
  // F(2^128) subtraction is XOR, so r − e = f2k_add_const(e, r)). Folds 4
  // factors per f2k_mul_poly (a degree-5 polynomial proof, no fresh VOLE) and
  // finishes the remainder with plain f2k_mul.
  F2kAuthValue eval_(const std::vector<F2kAuthValue> &v, block r) {
    F2kAuthValue acc;
    bb->f2k_add_const(acc, v[0], r);
    size_t i = 1;
    for (; i + 3 < v.size(); i += 4) {
      F2kAuthValue x[4];
      for (int j = 0; j < 4; ++j)
        bb->f2k_add_const(x[j], v[i + j], r);
      bb->f2k_mul_poly(acc, acc, x[0], x[1], x[2], x[3]);
    }
    for (; i < v.size(); ++i) {
      F2kAuthValue x;
      bb->f2k_add_const(x, v[i], r);
      bb->f2k_mul(acc, acc, x);
    }
    return acc;
  }

  // Open both product wires and check p_A(r) == p_B(r): the prover ships her
  // two MAC shares; the verifier folds them into its keys, recovering
  // val_A·Δ and val_B·Δ, and checks they match (⇒ val_A == val_B). Forging a
  // pass with val_A ≠ val_B would require guessing Δ.
  void open_eq_(const F2kAuthValue &pa, const F2kAuthValue &pb) {
    block macs[2] = { pa.mac, pb.mac };
    if (bb->party == ALICE) {
      bb->io->send_data(macs, 2 * sizeof(block));
      bb->io->flush();
    } else {
      block recv[2];
      bb->io->recv_data(recv, 2 * sizeof(block));
      macs[0] = macs[0] ^ recv[0];
      macs[1] = macs[1] ^ recv[1];
      if (memcmp(macs, macs + 1, sizeof(block)) != 0)
        error("ZKPermProof: A is not a permutation of B");
    }
  }
};

} // namespace emp
#endif // EMP_ZK_PERM_PROOF_H__
