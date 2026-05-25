#ifndef EMP_ZK_BOOL_H__
#define EMP_ZK_BOOL_H__
#include "emp-zk/emp-zk-bool/polynomial.h"
#include "emp-zk/emp-zk-bool/zk_bool_base.h"

namespace emp {
using namespace std;

inline void setup_zk_bool(BoolIO *io, int party) {
  if (party == ALICE)
    backend = new ZKBoolProver(io);
  else
    backend = new ZKBoolVerifier(io);
}

// Verifier-only. Returns the global MAC secret Δ. Only the verifier
// holds it; calling on the prover side is a programmer error.
inline block get_bool_delta() { return get_bool_backend_ver()->delta; }

inline void sync_zk_bool() { get_bool_backend()->io->flush(); }

inline void finalize_zk_bool() {
  delete backend;
  backend = nullptr;
}

inline void zkp_poly_deg2(Bit *x, Bit *y, bool *coeff, int64_t len) {
  get_bool_backend()->polyproof->zkp_poly_deg2((block *)x, (block *)y, coeff,
                                               len);
}

inline void zkp_inner_prdt(Bit *x, Bit *y, bool constant, int64_t len) {
  get_bool_backend()->polyproof->zkp_inner_prdt((block *)x, (block *)y,
                                                constant, len);
}

inline void zkp_inner_prdt_eq(Bit *x, Bit *y, Bit *r, Bit *s, int64_t len,
                              int64_t len2) {
  get_bool_backend()->polyproof->zkp_inner_prdt_eq(
      (block *)x, (block *)y, (block *)r, (block *)s, len, len2);
}

inline void zkp_inner_prdt_eq(Bit *x, Bit *y, Bit *r, Bit *s, Bit *rr, Bit *ss,
                              int64_t len, int64_t len2) {
  get_bool_backend()->polyproof->zkp_inner_prdt_eq(
      (block *)x, (block *)y, (block *)r, (block *)s, (block *)rr, (block *)ss,
      len, len2);
}

inline void zkp_inner_prdt_multi(SignedInt *x, SignedInt *y, Bit *r, Bit *s,
                                 int64_t len, int64_t width) {
  get_bool_backend()->polyproof->zkp_inner_prdt_multi(x, y, r, s, len, width);
}

} // namespace emp

// Multiset permutation-check gadget (the core of VOLE-ZK RAM/ROM). Generic
// over f2k wires; depends only on the backend above.
#include "emp-zk/emp-zk-bool/zk_perm_proof.h"

// RAM-ZK circuits build directly on this backend — they call
// get_bool_backend(), sync_zk_bool(), and the f2k wire ops above — so they
// live here rather than as a separate module. Included after the namespace
// block so sync_zk_bool() is already declared.
#include "emp-zk/emp-zk-bool/zk_set.h"
#include "emp-zk/emp-zk-bool/zk_ram.h"

#endif
