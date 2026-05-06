#ifndef ZK_BOOL_CIRCUIT_EXE_H__
#define ZK_BOOL_CIRCUIT_EXE_H__
#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk-bool/polynomial.h"
#include <iostream>

using namespace emp;

// Free-standing helper since v1.0; the v0.3.x CircuitExecution base is gone.
// The two gate engines that subclass this (ZKBoolCircExecPrv/Ver) plug into
// the unified Backend* via the wrapper in zk_bool_backend.h, which forwards
// Backend's void* virtuals here.
template <typename IO> class ZKBoolCircExec {
public:
  int64_t gid = 0;
  OSTriple<IO> *ostriple;
  PolyProof<IO> *polyproof;
  block pub_label[2];
  virtual ~ZKBoolCircExec() = default;
  uint64_t communication() { return ostriple->communication(); }
  block and_gate(const block &a, const block &b) {
    ++gid;
    return ostriple->auth_compute_and(a, b);
  }
  block xor_gate(const block &a, const block &b) { return a ^ b; }
  virtual block not_gate(const block &a) { return a ^ makeBlock(0, 1); }
  block public_label(bool b) { return pub_label[b]; }
  uint64_t num_and() { return gid; }
  void sync() {
    for (int i = 0; i < ostriple->threads; ++i)
      ostriple->ios[i]->flush();
  }
};
#endif // ZK_BOOLEAN_GEN_H__
