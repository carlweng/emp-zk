#ifndef EMP_SVOLE_FIELD_POLICY_H__
#define EMP_SVOLE_FIELD_POLICY_H__

// FieldPolicy: the field-specific surface of the unified sVOLE
// protocol. A policy bundles (subfield K, extension F, ops, generator
// + bootstrap protocol) so the rest of the protocol stack
// (MpfssReg, LpnAmplifier, SVole orchestrator) can be templated and
// shared across F2k, F_p, and future field instantiations.
//
// One sVOLE pair is an AuthValue<P> = (K val, F mac) with the
// invariant
//
//     mac_alice = mac_bob + embed(val) · Δ        in F
//
// where Δ ∈ F is the BOB-side global secret and `embed: K → F` is
// the policy's K-to-F lift, implicitly defined by the bootstrap
// generator (Galois packing for F2k, COPE for F_p).
//
// A `FieldPolicy` is a plain struct (no virtuals) providing:
//
//   using K        — subfield element type (cleartext)
//   using F        — extension field element type (MAC)
//
//   // F ops (used by MpfssReg, LpnAmplifier, MAC check, chi-fold)
//   static F    f_zero();
//   static F    f_add (F a, F b);
//   static F    f_sub (F a, F b);
//   static F    f_mul (F a, F b);
//   static bool f_eq  (F a, F b);
//
//   // K → F embedding (so `embed(val) · Δ` makes sense in F).
//   static F    embed     (K x);
//   static F    scalar_mul(K x, F y);             // = f_mul(embed(x), y)
//
//   // K ops (minimal; caller convenience)
//   static K    k_zero();
//   static K    k_add(K a, K b);
//
//   // Bootstrap: OT → small sVOLE.
//   //   F2k: 128 ferret COTs → 1 (val, mac) via Galois packing.
//   //   F_p: 61 ferret COTs + tau corrections per element (COPE).
//   template <typename IO>
//   class Bootstrap {
//    public:
//     Bootstrap(int party, IO *io, FerretCOT *ferret, F Delta = f_zero());
//     void extend(AuthValue<FieldPolicy> *out, int64_t num);
//   };
//
// See f2k_policy.h for the concrete F_2 ⊂ F_{2^128} instantiation.

namespace emp {

template <typename P>
struct AuthValue {
  typename P::K val;     // subfield cleartext; ALICE holds the secret,
                         // BOB's copy is zeroed.
  typename P::F mac;     // extension MAC share; both parties hold their
                         // side, satisfying the relation above.
};

} // namespace emp
#endif
