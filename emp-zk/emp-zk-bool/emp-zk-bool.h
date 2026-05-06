#ifndef EMP_ZK_BOOL_H__
#define EMP_ZK_BOOL_H__
#include "emp-zk/emp-zk-bool/cheat_record.h"
#include "emp-zk/emp-zk-bool/ostriple.h"
#include "emp-zk/emp-zk-bool/polynomial.h"
#include "emp-zk/emp-zk-bool/zk_bool_backend.h"
#include "emp-zk/emp-zk-bool/zk_bool_circuit_exec.h"
#include "emp-zk/emp-zk-bool/zk_prover.h"
#include "emp-zk/emp-zk-bool/zk_verifier.h"

namespace emp {
template <typename IO>
inline void setup_zk_bool(IO **ios, int threads, int party,
                          void *state = nullptr) {
  CheatRecord::reset();
  if (party == ALICE)
    backend = new ZKBoolBackendPrv<IO>(ios, threads, state);
  else
    backend = new ZKBoolBackendVer<IO>(ios, threads, state);
}

template <typename IO> inline block get_bool_delta(int party) {
  if (party == BOB)
    return static_cast<ZKBoolBackendVer<IO> *>(backend)->proto->ostriple->delta;
  else
    return zero_block;
}

template <typename IO> inline void sync_zk_bool() {
  get_bool_circ<IO>()->sync();
}

template <typename IO> inline bool finalize_zk_bool() {
  delete backend;
  backend = nullptr;
  return CheatRecord::cheated();
}

template <typename IO>
inline void zkp_poly_deg2(Bit *x, Bit *y, bool *coeff, int len) {
  get_bool_circ<IO>()->polyproof->zkp_poly_deg2((block *)x, (block *)y, coeff,
                                                len);
}

template <typename IO>
inline void zkp_inner_prdt(Bit *x, Bit *y, bool constant, int len) {
  get_bool_circ<IO>()->polyproof->zkp_inner_prdt((block *)x, (block *)y,
                                                 constant, len);
}

template <typename IO>
inline void zkp_inner_prdt_eq(Bit *x, Bit *y, Bit *r, Bit *s, int len,
                              int len2) {
  get_bool_circ<IO>()->polyproof->zkp_inner_prdt_eq(
      (block *)x, (block *)y, (block *)r, (block *)s, len, len2);
}

template <typename IO>
inline void zkp_inner_prdt_eq(Bit *x, Bit *y, Bit *r, Bit *s, Bit *rr, Bit *ss,
                              int len, int len2) {
  get_bool_circ<IO>()->polyproof->zkp_inner_prdt_eq(
      (block *)x, (block *)y, (block *)r, (block *)s, (block *)rr, (block *)ss,
      len, len2);
}

template <typename IO>
inline void zkp_inner_prdt_multi(Integer *x, Integer *y, Bit *r, Bit *s,
                                 int len, int width) {
  get_bool_circ<IO>()->polyproof->zkp_inner_prdt_multi(x, y, r, s, len, width);
}

} // namespace emp
#endif
