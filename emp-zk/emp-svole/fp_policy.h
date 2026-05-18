#ifndef EMP_SVOLE_FP_POLICY_H__
#define EMP_SVOLE_FP_POLICY_H__

#include "emp-zk/emp-svole/fp_base_svole.h"
#include "emp-zk/emp-svole/fp_utility.h"

// F_p sVOLE: default policy for FpVOLE.
//
// Mersenne 2^61 − 1. K = F = uint64_t (one F_p element). AuthValue is
// mac-first packed so its bytes alias 1:1 with the historical
// `(val << 64) | mac` packing in __uint128_t; this lets the internal
// F_p machinery (FpCope, FpMpfssReg, FpLpnAmp) keep operating on
// __uint128_t* via reinterpret_cast for SIMD.
//
// User extension surface: define an alternate Policy with the same
// nested types/methods to support a different prime. A future
// GenericPrimePolicy<__uint128_t P> would slot in here with multi-
// limb mod-p ops and a different M (basis size) for COPE.

namespace emp {

struct MersennePolicy61 {
  using F = uint64_t;
  using K = uint64_t;

  // mac-first layout: bytes match `(val << 64) | mac` packing in
  // __uint128_t (low 64 = mac, high 64 = val).
  struct AuthValue {
    uint64_t mac;
    uint64_t val;
  };

  static constexpr uint64_t PR_VAL = (1ULL << 61) - 1;
  static constexpr int M = 61;          // basis size for COPE

  // F ops (Mersenne arithmetic, defined in fp_utility.h)
  static inline F    f_zero()              { return 0; }
  static inline F    f_add (F a, F b)      { return add_mod(a, b); }
  static inline F    f_sub (F a, F b)      { return a >= b ? a - b : a + PR_VAL - b; }
  static inline F    f_mul (F a, F b)      { return mult_mod(a, b); }
  static inline bool f_eq  (F a, F b)      { return a == b; }

  static inline F    embed     (K x)       { return x; }
  static inline F    scalar_mul(K x, F y)  { return mult_mod(x, y); }

  static inline K    k_zero()              { return 0; }
  static inline K    k_add (K a, K b)      { return add_mod(a, b); }

  // OT → sVOLE bootstrap: wraps Base_svole (COPE-essential). Bytes of
  // AuthValue match `(val << 64) | mac`, so Base_svole::triple_gen_send/
  // recv writes directly into the AuthValue buffer via reinterpret_cast.
  template <typename IO> class Bootstrap {
   public:
    int party;
    IO *io;
    F Delta;
    Bootstrap(int party, IO *io, Ferret * /*ferret*/, F delta = 0)
        : party(party), io(io), Delta(delta) {}

    void extend(AuthValue *out, int64_t num) {
      __uint128_t *buf = (__uint128_t *)out;
      if (party == ALICE) {
        Base_svole<IO> bv(party, io, (__uint128_t)Delta);
        bv.triple_gen_send(buf, num);
      } else {
        Base_svole<IO> bv(party, io);
        bv.triple_gen_recv(buf, num);
      }
    }
  };
};

} // namespace emp
#endif
