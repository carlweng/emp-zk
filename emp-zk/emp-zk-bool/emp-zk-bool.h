#ifndef EMP_ZK_BOOL_H__
#define EMP_ZK_BOOL_H__
#include "emp-zk/emp-zk-bool/polynomial.h"
#include "emp-zk/emp-zk-bool/zk_bool_base.h"

namespace emp {

inline void setup_zk_bool(BoolIO *io, int party) {
  if (party == ALICE)
    backend = new ZKBoolProver(io);
  else
    backend = new ZKBoolVerifier(io);
}

// Verifier-only. Returns the global MAC secret Δ. Only the verifier
// holds it; calling on the prover side is a programmer error.
inline block get_bool_delta() { return get_bool_backend_ver()->delta; }

inline void sync_zk_bool() { get_bool_backend()->sync(); }

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

inline void zkp_inner_prdt_multi(Integer *x, Integer *y, Bit *r, Bit *s,
                                 int64_t len, int64_t width) {
  get_bool_backend()->polyproof->zkp_inner_prdt_multi(x, y, r, s, len, width);
}

} // namespace emp
#endif
