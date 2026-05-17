#ifndef EMP_SVOLE_F2K_POLICY_H__
#define EMP_SVOLE_F2K_POLICY_H__

#include "emp-ot/emp-ot.h"
#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-svole/field_policy.h"

// F_2 ⊂ F_{2^128}: the binary instantiation of the unified sVOLE.
//
// K = F = block. K is interpreted as an F_2-vector of 128 bits; F is
// the field F_{2^128} with the polynomial basis {1, X, …, X^127}. The
// `embed: K → F` map is the identity at the C++ type level — the
// Galois packing in the bootstrap is what makes the F_2-vector view
// of `val` line up with the field-element view of `mac`. F_2-linearity
// of the lift means the OT-to-sVOLE bootstrap needs no wire traffic.

namespace emp {

struct F2kPolicy {
  using K = block;
  using F = block;

  // F ops
  static inline F    f_zero()              { return zero_block; }
  static inline F    f_add (F a, F b)      { return a ^ b; }
  static inline F    f_sub (F a, F b)      { return a ^ b; }
  static inline F    f_mul (F a, F b)      { block r; gfmul(a, b, &r); return r; }
  static inline bool f_eq  (F a, F b)      { return cmpBlock(&a, &b, 1); }

  // K → F lift
  static inline F    embed     (K x)       { return x; }
  static inline F    scalar_mul(K x, F y)  { return f_mul(x, y); }

  // K ops
  static inline K    k_zero()              { return zero_block; }
  static inline K    k_add (K a, K b)      { return a ^ b; }

  // OT → sVOLE bootstrap: 128 ferret COTs per output pair, packed via
  // GaloisFieldPacking. No wire traffic — relies on F_2-linearity of
  // the polynomial basis {1, X, …, X^127} so that
  //
  //   lift(m_0, …, m_127) = lift(k_0, …, k_127) + Δ · lift(x_0, …, x_127)
  //
  // aggregates 128 binary COTs into one sVOLE pair in F_{2^128}.
  template <typename IO>
  class Bootstrap {
   public:
    int party;
    IO *io;
    FerretCOT *ferret = nullptr;
    block delta;
    GaloisFieldPacking pack;

    Bootstrap(int party, IO *io, FerretCOT *ferret, F /*Delta unused*/ = zero_block)
        : party(party), io(io), ferret(ferret) {
      if (party == BOB) delta = ferret->Delta;
    }

    void extend(AuthValue<F2kPolicy> *out, int64_t num) {
      // Pull num*128 OTs out of the long-lived ferret session via
      // rcot_*_next chunks. Caller must have an open ferret session
      // (the bool backend opens one ctor->dtor; standalone tests have
      // to open it explicitly).
      std::vector<block> ferret_buffer((std::size_t)num * 128);
      const int64_t chunk = ferret->chunk_ots();
      std::vector<block> chunk_buf(chunk);
      int64_t needed = num * 128, got = 0;
      // ferret_party = 3-party; ferret is the OT-sender exactly when
      // this side is BOB.
      const bool sender = (party == BOB);
      while (got < needed) {
        if (sender) ferret->rcot_send_next(chunk_buf.data());
        else        ferret->rcot_recv_next(chunk_buf.data());
        int64_t take = std::min(chunk, needed - got);
        std::memcpy(ferret_buffer.data() + got, chunk_buf.data(),
                    take * sizeof(block));
        got += take;
      }
      std::size_t j = 0;
      for (std::size_t i = 0; i < (std::size_t)num; ++i) {
        if (party == ALICE) {
          bool val_b[128];
          for (int k = 0; k < 128; ++k)
            val_b[k] = getLSB(ferret_buffer[j + k]);
          out[i].val = bool_to_block(val_b);
        } else {
          out[i].val = zero_block;
        }
        pack.packing(&out[i].mac, ferret_buffer.data() + j);
        j += 128;
      }
    }
  };
};

} // namespace emp
#endif
