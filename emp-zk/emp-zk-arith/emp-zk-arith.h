#ifndef EMP_ZK_ARITH_H__
#define EMP_ZK_ARITH_H__
#include "emp-zk/emp-zk-arith/conversion.h"
#include "emp-zk/emp-zk-arith/int_fp.h"
#include "emp-zk/emp-zk-arith/ostriple.h"
#include "emp-zk/emp-zk-arith/polynomial.h"
#include "emp-zk/emp-zk-arith/triple_auth.h"
#include "emp-zk/emp-zk-arith/zk_fp_exec.h"
#include "emp-zk/emp-zk-arith/zk_fp_exec_prover.h"
#include "emp-zk/emp-zk-arith/zk_fp_exec_verifier.h"
#include "emp-zk/emp-zk-bool/zk_bool_base.h"

namespace emp {
using namespace std;

// Arithmetic-only setup (no bool<->arith conversion).
inline void setup_zk_arith(BoolIO *io, int party) {
  if (party == ALICE) {
    ZKFpExec::zk_exec = new ZKFpExecPrv(io);
    FpPolyProof::fppolyproof =
        new FpPolyProof(ALICE, io,
                            ((ZKFpExecPrv *)(ZKFpExec::zk_exec))->ostriple);
  } else {
    ZKFpExec::zk_exec = new ZKFpExecVer(io);
    FpPolyProof::fppolyproof = new FpPolyProof(
        BOB, io, ((ZKFpExecVer *)(ZKFpExec::zk_exec))->ostriple);
  }
}

// Setup with bool<->arith conversion. `bool_sess` is the live ZKBoolSession the
// conversion shares (its engine / Δ); the caller keeps it alive until after
// finalize_zk_arith().
inline void setup_zk_arith(BoolIO *io, int party, ZKBoolSession &bool_sess) {
  setup_zk_arith(io, party);
  if (party == ALICE) {
    EdaBits::conv = new EdaBits(
        bool_sess, io, ((ZKFpExecPrv *)(ZKFpExec::zk_exec))->ostriple->vole);
  } else {
    EdaBits::conv = new EdaBits(
        bool_sess, io, ((ZKFpExecVer *)(ZKFpExec::zk_exec))->ostriple->vole);
    EdaBits::conv->install_boolean(bool_sess.engine().delta);
  }
}

inline void finalize_zk_arith() {
  if (EdaBits::conv != nullptr)
    delete EdaBits::conv;
  delete FpPolyProof::fppolyproof;
  delete ZKFpExec::zk_exec;
}
}  // namespace emp

#endif
