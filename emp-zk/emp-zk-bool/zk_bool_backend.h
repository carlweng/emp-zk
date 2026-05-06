#ifndef EMP_ZK_BOOL_BACKEND_H__
#define EMP_ZK_BOOL_BACKEND_H__

// emp-zk-bool's plug into the unified Backend* backend on emp-tool
// main. The v0.3.x design split the same machinery across two
// classes (ZKBoolCircExec for AND/XOR/NOT/public-label and
// ZKProver/ZKVerifier for input feeding + output revealing) wired
// up via the two static singletons CircuitExecution::circ_exec and
// ProtocolExecution::prot_exec. Backend collapses both singletons
// into one virtual interface, and the prover- and verifier-side
// state is small enough to live on a single Backend subclass per
// party — no helper proxy, no composition layer. The host file
// (emp-zk-bool.h) installs / tears down `backend` via setup_zk_bool
// / finalize_zk_bool; cross-module consumers reach the per-side
// instance through the get_bool_* accessors at the bottom.

#include <emp-tool/emp-tool.h>

#include "emp-zk/emp-zk-bool/ostriple.h"
#include "emp-zk/emp-zk-bool/polynomial.h"

namespace emp {

// Common ground for the prover- and verifier-side backends. Holds
// the per-party state that's identical on both sides (the
// authenticated-triple stream, the polynomial-proof helper, the
// public-input label table) and implements the symmetric gate ops
// (AND / XOR / public-label). NOT and feed/reveal differ between
// sides and live on the subclasses.
template <typename IO> class ZKBoolBackendBase : public Backend {
public:
  int64_t gid = 0;
  block pub_label[2];
  IO *io = nullptr;
  OSTriple<IO> *ostriple = nullptr;
  PolyProof<IO> *polyproof = nullptr;

  ZKBoolBackendBase(int p) : Backend(p) {}
  ~ZKBoolBackendBase() override {
    delete polyproof;
    delete ostriple;
  }

  size_t wire_bytes() const override { return sizeof(block); }

  void public_label(void *o, bool b) override {
    *static_cast<block *>(o) = pub_label[b];
  }
  void and_gate(void *o, const void *l, const void *r) override {
    ++gid;
    *static_cast<block *>(o) = ostriple->auth_compute_and(
        *static_cast<const block *>(l), *static_cast<const block *>(r));
  }
  void xor_gate(void *o, const void *l, const void *r) override {
    *static_cast<block *>(o) =
        *static_cast<const block *>(l) ^ *static_cast<const block *>(r);
  }
  uint64_t num_and() override { return gid; }

  // feed()'s body is symmetric: ALICE-input goes through the OT-
  // backed authenticated_bits_input, PUBLIC-input is just the pub
  // label table. Both sides share this body even though OSTriple's
  // own role-aware code distinguishes party at the wire level.
  void feed(void *out, int from_party, const bool *in, size_t n) override {
    block *label = static_cast<block *>(out);
    if (from_party == ALICE)
      ostriple->authenticated_bits_input(label, in, static_cast<int>(n));
    else if (from_party == PUBLIC)
      for (size_t i = 0; i < n; ++i)
        label[i] = pub_label[in[i]];
  }

  void sync() {
    for (int i = 0; i < ostriple->threads; ++i)
      ostriple->ios[i]->flush();
  }
};

// Prover side. NOT is the canonical XOR-with-1 trick; reveal()
// either returns the LSB locally (to_party == ALICE) or runs the
// MAC-checked verify_output protocol (to_party == BOB / PUBLIC).
template <typename IO> class ZKBoolBackendPrv : public ZKBoolBackendBase<IO> {
public:
  using base = ZKBoolBackendBase<IO>;
  using base::io;
  using base::ostriple;
  using base::polyproof;
  using base::pub_label;

  ZKBoolBackendPrv(IO **ios, int threads, void *state) : base(ALICE) {
    PRG prg(fix_key);
    prg.random_block(pub_label, 2);
    pub_label[0] =
        pub_label[0] & makeBlock(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFEULL);
    pub_label[1] =
        pub_label[1] & makeBlock(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFEULL);
    pub_label[1] = pub_label[1] ^ makeBlock(0, 1);

    io = ios[0];
    ostriple = new OSTriple<IO>(ALICE, threads, ios, state);
    polyproof = new PolyProof<IO>(ALICE, ios[0], ostriple->ferret);
  }

  void not_gate(void *o, const void *in) override {
    *static_cast<block *>(o) =
        *static_cast<const block *>(in) ^ makeBlock(0, 1);
  }
  void reveal(bool *out, int to_party, const void *in, size_t n) override {
    const block *label = static_cast<const block *>(in);
    int len = static_cast<int>(n);
    if (to_party == ALICE) {
      for (int i = 0; i < len; ++i)
        out[i] = getLSB(label[i]);
    } else { // BOB or PUBLIC
      ostriple->verify_output(out, label, len);
    }
  }
};

// Verifier side. Holds the global secret `delta`; NOT folds zdelta
// (= delta ^ 1) so that authenticated wires keep their MAC under
// negation. reveal() only handles the BOB/PUBLIC case (the verifier
// never has a value to reveal locally).
template <typename IO> class ZKBoolBackendVer : public ZKBoolBackendBase<IO> {
public:
  using base = ZKBoolBackendBase<IO>;
  using base::io;
  using base::ostriple;
  using base::polyproof;
  using base::pub_label;

  block delta, zdelta;

  ZKBoolBackendVer(IO **ios, int threads, void *state) : base(BOB) {
    PRG prg(fix_key);
    prg.random_block(pub_label, 2);
    pub_label[0] =
        pub_label[0] & makeBlock(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFEULL);
    pub_label[1] =
        pub_label[1] & makeBlock(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFEULL);

    io = ios[0];
    ostriple = new OSTriple<IO>(BOB, threads, ios, state);
    polyproof = new PolyProof<IO>(BOB, ios[0], ostriple->ferret);
    polyproof->delta = ostriple->delta;

    delta = ostriple->delta;
    zdelta = delta ^ makeBlock(0, 1);
    pub_label[1] = pub_label[1] ^ zdelta;
  }

  void not_gate(void *o, const void *in) override {
    *static_cast<block *>(o) = *static_cast<const block *>(in) ^ zdelta;
  }
  void reveal(bool *out, int to_party, const void *in, size_t n) override {
    if (to_party == BOB || to_party == PUBLIC)
      ostriple->verify_output(out, static_cast<const block *>(in),
                              static_cast<int>(n));
  }
};

// Cross-module accessors. edabit / arith / ram-zk reach into the
// bool backend for ostriple / polyproof / delta — the cast asserts
// in debug if the global `backend` isn't actually one of ours.
template <typename IO> inline ZKBoolBackendBase<IO> *get_bool_backend() {
  return static_cast<ZKBoolBackendBase<IO> *>(backend);
}
template <typename IO> inline ZKBoolBackendPrv<IO> *get_bool_backend_prv() {
  return static_cast<ZKBoolBackendPrv<IO> *>(backend);
}
template <typename IO> inline ZKBoolBackendVer<IO> *get_bool_backend_ver() {
  return static_cast<ZKBoolBackendVer<IO> *>(backend);
}

// Source-compat aliases so existing callers keep building. The
// returned pointer no longer points at a separate ZKBoolCircExec
// object; it's the Backend subclass itself, which carries the same
// ostriple / polyproof / delta members.
template <typename IO> inline ZKBoolBackendBase<IO> *get_bool_circ() {
  return get_bool_backend<IO>();
}
template <typename IO> inline ZKBoolBackendPrv<IO> *get_bool_circ_prv() {
  return get_bool_backend_prv<IO>();
}
template <typename IO> inline ZKBoolBackendVer<IO> *get_bool_circ_ver() {
  return get_bool_backend_ver<IO>();
}

} // namespace emp
#endif
