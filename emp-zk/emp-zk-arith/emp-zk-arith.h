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

inline void setup_zk_arith(BoolIO *io, int party,
                           bool enable_conversion = false) {
  if (enable_conversion) {
    if (emp::backend == nullptr) {
      error("Boolean ZK backend is not set up!\n");
    }
  }

  if (party == ALICE) {
    ZKFpExec::zk_exec = new ZKFpExecPrv(io);
    FpPolyProof::fppolyproof =
        new FpPolyProof(ALICE, io,
                            ((ZKFpExecPrv *)(ZKFpExec::zk_exec))->ostriple);

    if (enable_conversion)
      EdaBits::conv = new EdaBits(
          ALICE, io,
          ((ZKFpExecPrv *)(ZKFpExec::zk_exec))->ostriple->vole);

  } else {
    ZKFpExec::zk_exec = new ZKFpExecVer(io);
    FpPolyProof::fppolyproof = new FpPolyProof(
        BOB, io, ((ZKFpExecVer *)(ZKFpExec::zk_exec))->ostriple);
    if (enable_conversion) {
      EdaBits::conv = new EdaBits(
          BOB, io,
          ((ZKFpExecVer *)(ZKFpExec::zk_exec))->ostriple->vole);
      EdaBits::conv->install_boolean(emp::get_bool_delta());
    }
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
