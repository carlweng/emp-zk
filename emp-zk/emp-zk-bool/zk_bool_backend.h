#ifndef EMP_ZK_BOOL_BACKEND_H__
#define EMP_ZK_BOOL_BACKEND_H__

// Backend wrapper for emp-zk-bool. emp-tool main collapsed
// CircuitExecution::circ_exec and ProtocolExecution::prot_exec into a
// single global Backend* backend; this class fuses the v0.3.x
// ZKBoolCircExec (gate engine) and ZKProver / ZKVerifier (input
// feeder + output revealer) by composition and exposes the unified
// Backend interface to emp-tool.
//
// Wrapper-by-composition (rather than refactoring the helpers
// themselves to inherit Backend) keeps the v0.3.x-shape gate methods
// — `block and_gate(const block&, const block&)` etc. — intact, so
// PolyProof / OSTriple / EdaBits / arith continue to call them
// unchanged. The `void*` ↔ `block*` conversion happens here.

#include <emp-tool/emp-tool.h>

#include "emp-zk/emp-zk-bool/zk_bool_circuit_exec.h"
#include "emp-zk/emp-zk-bool/zk_prover.h"
#include "emp-zk/emp-zk-bool/zk_verifier.h"

namespace emp {

template <typename IO> class ZKBoolBackendBase : public Backend {
public:
  ZKBoolCircExec<IO> *circ = nullptr;
  ZKBoolBackendBase(int party_) : Backend(party_) {}

  size_t wire_bytes() const override { return sizeof(block); }

  void public_label(void *o, bool b) override {
    *static_cast<block *>(o) = circ->public_label(b);
  }
  void and_gate(void *o, const void *l, const void *r) override {
    *static_cast<block *>(o) =
        circ->and_gate(*static_cast<const block *>(l),
                       *static_cast<const block *>(r));
  }
  void xor_gate(void *o, const void *l, const void *r) override {
    *static_cast<block *>(o) =
        circ->xor_gate(*static_cast<const block *>(l),
                       *static_cast<const block *>(r));
  }
  void not_gate(void *o, const void *in) override {
    *static_cast<block *>(o) =
        circ->not_gate(*static_cast<const block *>(in));
  }
  uint64_t num_and() override { return circ->num_and(); }
};

template <typename IO> class ZKBoolBackendPrv : public ZKBoolBackendBase<IO> {
public:
  ZKProver<IO> *proto = nullptr;
  using ZKBoolBackendBase<IO>::circ;

  ZKBoolBackendPrv(IO **ios, int threads, void *state)
      : ZKBoolBackendBase<IO>(ALICE) {
    auto *t = new ZKBoolCircExecPrv<IO>();
    circ = t;
    proto = new ZKProver<IO>(ios, threads, t, state);
  }
  ~ZKBoolBackendPrv() override {
    delete proto;
    delete circ;
  }

  void feed(void *out, int from_party, const bool *in, size_t n) override {
    proto->feed(static_cast<block *>(out), from_party, in,
                static_cast<int>(n));
  }
  void reveal(bool *out, int to_party, const void *in, size_t n) override {
    proto->reveal(out, to_party, static_cast<const block *>(in),
                  static_cast<int>(n));
  }
};

template <typename IO> class ZKBoolBackendVer : public ZKBoolBackendBase<IO> {
public:
  ZKVerifier<IO> *proto = nullptr;
  using ZKBoolBackendBase<IO>::circ;

  ZKBoolBackendVer(IO **ios, int threads, void *state)
      : ZKBoolBackendBase<IO>(BOB) {
    auto *t = new ZKBoolCircExecVer<IO>();
    circ = t;
    proto = new ZKVerifier<IO>(ios, threads, t, state);
  }
  ~ZKBoolBackendVer() override {
    delete proto;
    delete circ;
  }

  void feed(void *out, int from_party, const bool *in, size_t n) override {
    proto->feed(static_cast<block *>(out), from_party, in,
                static_cast<int>(n));
  }
  void reveal(bool *out, int to_party, const void *in, size_t n) override {
    proto->reveal(out, to_party, static_cast<const block *>(in),
                  static_cast<int>(n));
  }
};

// Side-agnostic accessors used by edabit / arith / extensions when
// they need to reach into the bool backend's helpers. The cast
// asserts in debug if the global `backend` isn't actually a
// ZKBoolBackend instance.
template <typename IO> inline ZKBoolCircExec<IO> *get_bool_circ() {
  return static_cast<ZKBoolBackendBase<IO> *>(backend)->circ;
}
template <typename IO> inline ZKBoolCircExecPrv<IO> *get_bool_circ_prv() {
  return static_cast<ZKBoolCircExecPrv<IO> *>(
      static_cast<ZKBoolBackendBase<IO> *>(backend)->circ);
}
template <typename IO> inline ZKBoolCircExecVer<IO> *get_bool_circ_ver() {
  return static_cast<ZKBoolCircExecVer<IO> *>(
      static_cast<ZKBoolBackendBase<IO> *>(backend)->circ);
}

} // namespace emp
#endif
