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
// party — no helper proxy, no composition layer.
//
// De-templated alongside the rest of the toolkit (emp-tool / emp-ot
// / emp-sh2pc): `io` is an IOChannel*, `ios` is an IOChannel**,
// and consumers no longer carry a `<NetIO>` / `<BoolIO>` template
// parameter through. Wires stay block (the GC-style label) and the
// gate ops keep the same shape.

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
class ZKBoolBackendBase : public Backend {
public:
  int64_t gid = 0;
  block pub_label[2];
  OSTriple *ostriple = nullptr;
  PolyProof *polyproof = nullptr;

  ZKBoolBackendBase(int p, BoolIO **ios, int threads) : Backend(p) {
    PRG prg(fix_key);
    prg.random_block(pub_label, 2);
    pub_label[0] = OSTriple::clear_lsb(pub_label[0]);
    pub_label[1] = OSTriple::clear_lsb(pub_label[1]);
    ostriple = new OSTriple(p, threads, ios);
    polyproof = new PolyProof(p, ios[0], ostriple->ferret);
  }
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
class ZKBoolBackendPrv : public ZKBoolBackendBase {
public:
  ZKBoolBackendPrv(BoolIO **ios, int threads)
      : ZKBoolBackendBase(ALICE, ios, threads) {
    pub_label[1] = pub_label[1] ^ makeBlock(0, 1);
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
class ZKBoolBackendVer : public ZKBoolBackendBase {
public:
  block delta, zdelta;

  ZKBoolBackendVer(BoolIO **ios, int threads)
      : ZKBoolBackendBase(BOB, ios, threads) {
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
inline ZKBoolBackendBase *get_bool_backend() {
  return static_cast<ZKBoolBackendBase *>(backend);
}
inline ZKBoolBackendPrv *get_bool_backend_prv() {
  return static_cast<ZKBoolBackendPrv *>(backend);
}
inline ZKBoolBackendVer *get_bool_backend_ver() {
  return static_cast<ZKBoolBackendVer *>(backend);
}

} // namespace emp
#endif
