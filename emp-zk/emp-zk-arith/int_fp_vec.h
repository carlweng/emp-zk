#ifndef INT_FP_VEC_H__
#define INT_FP_VEC_H__

#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk-arith/int_fp.h"

namespace emp {
using namespace std;

class IntFpVecSpan;   // zero-copy view over a contiguous run of labels (below)

// IntFpVec — a batch of committed F_p values, the vectorized counterpart of
// IntFp. It stores `len` authenticated labels contiguously (val-first layout,
// identical to IntFp::value) and routes the expensive element-wise
// multiplication through ZKFpExec's *vectorized* mul_gate, which the engine
// services with the batched + threaded auth_compute_mul (one correction send
// for the whole batch, the per-element field arithmetic split across the
// worker pool). Additions and public scaling are local/element-wise, exactly
// as in IntFp.
//
// Each label is wire-format-identical to an IntFp committed the same way, so an
// IntFpVec is just `len` IntFp commitments laid out contiguously: operator[]
// hands back the matching scalar IntFp, and a span of IntFp can be wrapped
// without copying (the layouts match — see from_intfp / to_intfp below).
class IntFpVec {
public:
  std::vector<__uint128_t> value;   // authenticated labels (val-first layout)

  IntFpVec() {}
  explicit IntFpVec(int64_t len) : value((size_t)len) {}

  // Commit `len` values. party == ALICE/BOB: a fresh authenticated batch (the
  // prover supplies `input`, the verifier ignores it). party == PUBLIC: public
  // constants. Mirrors IntFp(uint64_t, party) but in one batched feed().
  IntFpVec(const uint64_t *input, int64_t len, int party = PUBLIC)
      : value((size_t)len) {
    if (party == PUBLIC) {
      for (int64_t i = 0; i < len; ++i)
        value[(size_t)i] = ZKFpExec::zk_exec->pub_label(input[i]);
    } else {
      // Batched authenticated input (one masked-difference exchange for all).
      ZKFpExec::zk_exec->feed(value.data(), input, len);
    }
  }

  int64_t size() const { return (int64_t)value.size(); }

  // Element-wise vectorized multiply: ONE batched, threaded auth_compute_mul
  // over all `len` independent products out_i = this_i * rhs_i. Equivalent to
  // `len` scalar IntFp multiplies but with a single batched correction send and
  // parallel field arithmetic. Operands must have equal length.
  IntFpVec operator*(const IntFpVec &rhs) const {
    const int64_t len = size();
    IntFpVec res(len);
    ZKFpExec::zk_exec->mul_gate(res.value.data(), this->value.data(),
                                rhs.value.data(), len);
    return res;
  }

  // Element-wise local add (no communication), like IntFp::operator+.
  IntFpVec operator+(const IntFpVec &rhs) const {
    const int64_t len = size();
    IntFpVec res(len);
    for (int64_t i = 0; i < len; ++i)
      res.value[(size_t)i] =
          ZKFpExec::zk_exec->add_gate(this->value[(size_t)i],
                                      rhs.value[(size_t)i]);
    return res;
  }

  // Element-wise local subtract: out_i = this_i - rhs_i = this_i + (p - rhs_i).
  IntFpVec operator-(const IntFpVec &rhs) const {
    const int64_t len = size();
    IntFpVec res(len);
    for (int64_t i = 0; i < len; ++i)
      res.value[(size_t)i] =
          ZKFpExec::zk_exec->sub_gate(this->value[(size_t)i],
                                      rhs.value[(size_t)i]);
    return res;
  }

  // ---- Public F_p constant ops (rhs is cleartext, broadcast to all) --------
  // No communication. * uses mul_const_gate; + / - use pub_label + add/sub.
  IntFpVec operator*(const uint64_t &rhs) const {
    const int64_t len = size();
    IntFpVec res(len);
    for (int64_t i = 0; i < len; ++i)
      res.value[(size_t)i] =
          ZKFpExec::zk_exec->mul_const_gate(this->value[(size_t)i], rhs);
    return res;
  }

  IntFpVec operator+(const uint64_t &rhs) const {
    const int64_t len = size();
    IntFpVec res(len);
    const __uint128_t pc = ZKFpExec::zk_exec->pub_label(rhs);  // one label, reused
    for (int64_t i = 0; i < len; ++i)
      res.value[(size_t)i] =
          ZKFpExec::zk_exec->add_gate(this->value[(size_t)i], pc);
    return res;
  }

  IntFpVec operator-(const uint64_t &rhs) const {
    const int64_t len = size();
    IntFpVec res(len);
    const __uint128_t pc = ZKFpExec::zk_exec->pub_label(rhs);
    for (int64_t i = 0; i < len; ++i)
      res.value[(size_t)i] =
          ZKFpExec::zk_exec->sub_gate(this->value[(size_t)i], pc);
    return res;
  }

  // ---- Element-wise public constant vectors (one constant per element) -----
  IntFpVec operator*(const std::vector<uint64_t> &rhs) const {
    const int64_t len = size();
    IntFpVec res(len);
    for (int64_t i = 0; i < len; ++i)
      res.value[(size_t)i] =
          ZKFpExec::zk_exec->mul_const_gate(this->value[(size_t)i], rhs[(size_t)i]);
    return res;
  }

  IntFpVec operator+(const std::vector<uint64_t> &rhs) const {
    const int64_t len = size();
    IntFpVec res(len);
    for (int64_t i = 0; i < len; ++i)
      res.value[(size_t)i] = ZKFpExec::zk_exec->add_gate(
          this->value[(size_t)i], ZKFpExec::zk_exec->pub_label(rhs[(size_t)i]));
    return res;
  }

  IntFpVec operator-(const std::vector<uint64_t> &rhs) const {
    const int64_t len = size();
    IntFpVec res(len);
    for (int64_t i = 0; i < len; ++i)
      res.value[(size_t)i] = ZKFpExec::zk_exec->sub_gate(
          this->value[(size_t)i], ZKFpExec::zk_exec->pub_label(rhs[(size_t)i]));
    return res;
  }

  // Per-element view as a scalar IntFp (shares the label).
  IntFp operator[](int64_t i) const {
    IntFp r;
    r.value = value[(size_t)i];
    return r;
  }

  // Sum of all committed elements as a single IntFp (local, no communication):
  // folds the labels with add_gate. An empty vector returns a public 0.
  IntFp sum() const {
    IntFp acc;
    const int64_t len = size();
    if (len == 0) {
      acc.value = ZKFpExec::zk_exec->pub_label(0);
      return acc;
    }
    acc.value = value[0];   // seed with element 0 (a committed value, no pub tag)
    for (int64_t i = 1; i < len; ++i)
      acc.value = ZKFpExec::zk_exec->add_gate(acc.value, value[(size_t)i]);
    return acc;
  }

  // Decompose this batch into `len` standalone IntFp elements. Each result is a
  // full IntFp commitment carrying element i's authenticated label (val-first),
  // so it can be used in any scalar IntFp op / revealed independently. The
  // returned vector owns copies of the labels (this IntFpVec is unchanged).
  std::vector<IntFp> decompose() const {
    std::vector<IntFp> out((size_t)size());
    for (int64_t i = 0; i < size(); ++i)
      out[(size_t)i].value = value[(size_t)i];
    return out;
  }

  // In-place decomposition into a caller-provided IntFp[len] (no allocation).
  void decompose(IntFp *out) const {
    for (int64_t i = 0; i < size(); ++i)
      out[i].value = value[(size_t)i];
  }

  // Batched cleartext extract: pull each element's VAL lane (low 64 bits of the
  // val-first label) into `out`, locally and with NO ZK op / communication.
  // On ALICE these are the committed cleartext values (handy for reference
  // reconstruction); on BOB the val lane is 0. Avoids decompose() + per-element
  // VAL(.value).
  void values(uint64_t *out) const {
    for (int64_t i = 0; i < size(); ++i)
      out[(size_t)i] = (uint64_t)(value[(size_t)i] & 0xFFFFFFFFFFFFFFFFULL);
  }
  std::vector<uint64_t> values() const {
    std::vector<uint64_t> out((size_t)size());
    values(out.data());
    return out;
  }

  // Batched reveal / check over the whole vector (one engine call).
  void reveal(uint64_t *out) {
    ZKFpExec::zk_exec->reveal(value.data(), out, size());
  }
  bool reveal_check(const uint64_t *expect) {
    ZKFpExec::zk_exec->reveal_check(value.data(),
                                    const_cast<uint64_t *>(expect), size());
    return true;
  }
  void reveal_check_zero() {
    ZKFpExec::zk_exec->reveal_check_zero(value.data(), size());
  }

  // Compose one IntFpVec from `len` individual IntFp (inverse of decompose).
  // Each element's authenticated label is copied in order; the resulting batch
  // is wire-identical to having committed those values together.
  static IntFpVec compose(const IntFp *a, int64_t len) {
    IntFpVec r(len);
    for (int64_t i = 0; i < len; ++i) r.value[(size_t)i] = a[i].value;
    return r;
  }
  static IntFpVec compose(const std::vector<IntFp> &a) {
    return compose(a.data(), (int64_t)a.size());
  }

  // Negate every element: -x = (p - x) componentwise (local, no comms).
  IntFpVec negate() const {
    const int64_t len = size();
    IntFpVec res(len);
    for (int64_t i = 0; i < len; ++i)
      res.value[(size_t)i] = ZKFpExec::zk_exec->neg_gate(this->value[(size_t)i]);
    return res;
  }

  // Zero-copy views into this vector's storage (NON-owning; valid only while
  // this IntFpVec is alive and not reallocated). Lets callers operate on a
  // sub-range [off, off+len) without composing a copy. Defined after
  // IntFpVecSpan below.
  IntFpVecSpan span();
  IntFpVecSpan subspan(int64_t off, int64_t len);
};

// IntFpVecSpan — a non-owning (pointer, length) view over a contiguous run of
// authenticated labels (e.g. a sub-range of an IntFpVec). It carries no
// storage, so slicing is O(1) with no copy; the element-wise ops read straight
// from the aliased buffer. Result-producing ops (multiply, add, ...) allocate a
// fresh owning IntFpVec for their OUTPUT (the inputs stay zero-copy); in-place
// negate() overwrites the viewed storage.
class IntFpVecSpan {
public:
  __uint128_t *p_ = nullptr;
  int64_t n_ = 0;

  IntFpVecSpan() {}
  IntFpVecSpan(__uint128_t *p, int64_t n) : p_(p), n_(n) {}

  int64_t size() const { return n_; }
  __uint128_t *data() const { return p_; }
  IntFpVecSpan subspan(int64_t off, int64_t len) const {
    return IntFpVecSpan(p_ + off, len);
  }
  IntFp operator[](int64_t i) const {
    IntFp r;
    r.value = p_[(size_t)i];
    return r;
  }

  // Vectorized multiply — inputs read in place from both spans, no copy.
  IntFpVec operator*(const IntFpVecSpan &rhs) const {
    IntFpVec res(n_);
    ZKFpExec::zk_exec->mul_gate(res.value.data(), p_, rhs.p_, n_);
    return res;
  }
  // Element-wise add / subtract of two spans (output is a new IntFpVec).
  IntFpVec operator+(const IntFpVecSpan &rhs) const {
    IntFpVec res(n_);
    for (int64_t i = 0; i < n_; ++i)
      res.value[(size_t)i] =
          ZKFpExec::zk_exec->add_gate(p_[(size_t)i], rhs.p_[(size_t)i]);
    return res;
  }
  IntFpVec operator-(const IntFpVecSpan &rhs) const {
    IntFpVec res(n_);
    for (int64_t i = 0; i < n_; ++i)
      res.value[(size_t)i] =
          ZKFpExec::zk_exec->sub_gate(p_[(size_t)i], rhs.p_[(size_t)i]);
    return res;
  }
  // Public-constant broadcast (output is a new IntFpVec).
  IntFpVec operator*(const uint64_t &c) const {
    IntFpVec res(n_);
    for (int64_t i = 0; i < n_; ++i)
      res.value[(size_t)i] = ZKFpExec::zk_exec->mul_const_gate(p_[(size_t)i], c);
    return res;
  }
  IntFpVec operator+(const uint64_t &c) const {
    IntFpVec res(n_);
    const __uint128_t pc = ZKFpExec::zk_exec->pub_label(c);
    for (int64_t i = 0; i < n_; ++i)
      res.value[(size_t)i] = ZKFpExec::zk_exec->add_gate(p_[(size_t)i], pc);
    return res;
  }
  IntFpVec operator-(const uint64_t &c) const {
    IntFpVec res(n_);
    const __uint128_t pc = ZKFpExec::zk_exec->pub_label(c);
    for (int64_t i = 0; i < n_; ++i)
      res.value[(size_t)i] = ZKFpExec::zk_exec->sub_gate(p_[(size_t)i], pc);
    return res;
  }

  // Sum of the viewed elements into a single IntFp (local fold).
  IntFp sum() const {
    IntFp acc;
    if (n_ == 0) {
      acc.value = ZKFpExec::zk_exec->pub_label(0);
      return acc;
    }
    acc.value = p_[0];
    for (int64_t i = 1; i < n_; ++i)
      acc.value = ZKFpExec::zk_exec->add_gate(acc.value, p_[(size_t)i]);
    return acc;
  }

  // In-place negation of the viewed storage (mutates the parent's labels).
  IntFpVecSpan &negate() {
    for (int64_t i = 0; i < n_; ++i)
      p_[(size_t)i] = ZKFpExec::zk_exec->neg_gate(p_[(size_t)i]);
    return *this;
  }

  // Decompose / reveal directly over the view (no copy of the inputs).
  std::vector<IntFp> decompose() const {
    std::vector<IntFp> out((size_t)n_);
    for (int64_t i = 0; i < n_; ++i) out[(size_t)i].value = p_[(size_t)i];
    return out;
  }
  // Batched cleartext VAL extract over the view (local, no ZK op).
  void values(uint64_t *out) const {
    for (int64_t i = 0; i < n_; ++i)
      out[(size_t)i] = (uint64_t)(p_[(size_t)i] & 0xFFFFFFFFFFFFFFFFULL);
  }
  std::vector<uint64_t> values() const {
    std::vector<uint64_t> out((size_t)n_);
    values(out.data());
    return out;
  }
  void reveal(uint64_t *out) const {
    ZKFpExec::zk_exec->reveal(p_, out, n_);
  }
  bool reveal_check(const uint64_t *expect) const {
    ZKFpExec::zk_exec->reveal_check(p_, const_cast<uint64_t *>(expect), n_);
    return true;
  }
  // Materialize an owning copy when an independent IntFpVec is needed.
  IntFpVec to_vec() const { return IntFpVec::compose(decompose()); }
};

inline IntFpVecSpan IntFpVec::span() {
  return IntFpVecSpan(value.data(), size());
}
inline IntFpVecSpan IntFpVec::subspan(int64_t off, int64_t len) {
  return IntFpVecSpan(value.data() + off, len);
}

}  // namespace emp

#endif
