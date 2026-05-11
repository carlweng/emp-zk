#ifndef EMP_SVOLE_SVOLE_H__
#define EMP_SVOLE_SVOLE_H__

#include "emp-zk/emp-svole/field_policy.h"
#include "emp-zk/emp-svole/lpn_amp.h"
#include "emp-zk/emp-svole/mpfss_reg.h"
#include "emp-zk/emp-svole/base_cot.h"
#include "emp-zk/emp-svole/preot.h"

// SVole<P, IO>: the unified sVOLE orchestrator.
//
// Three-layer pipeline over AuthValue<P>[] buffers:
//   1. P::Bootstrap<IO>     — OT (ferret) → small sVOLE in F
//   2. MpfssReg<P, IO>      — small sVOLE + GGM trees → t-sparse vector
//   3. LpnAmplifier<P, 10>  — t-sparse + carry-over → n pseudorandom sVOLE pairs
//
// Both parties hold AuthValue<P>[] buffers; the verifier only reads
// .mac, the prover writes both .val and .mac. Single-threaded, single-IO.

namespace emp {

class SVoleParam {
public:
  int64_t n, t, k, log_bin_sz, n_pre, t_pre, k_pre, log_bin_sz_pre;
  SVoleParam() {}
  SVoleParam(int64_t n, int64_t t, int64_t k, int64_t log_bin_sz,
             int64_t n_pre, int64_t t_pre, int64_t k_pre,
             int64_t log_bin_sz_pre)
      : n(n), t(t), k(k), log_bin_sz(log_bin_sz), n_pre(n_pre), t_pre(t_pre),
        k_pre(k_pre), log_bin_sz_pre(log_bin_sz_pre) {

    if (n != t * (1 << log_bin_sz) || n_pre != t_pre * (1 << log_bin_sz_pre) ||
        n_pre < k + t + 1)
      error("LPN parameter not matched");
  }
  int64_t buf_sz() const { return n - t - k - 1; }
};

const static SVoleParam svole_b13 =
    SVoleParam(10485760, 1280, 425000, 13, 470016, 918, 32768, 9);
const static SVoleParam svole_b12 =
    SVoleParam(10268672, 2507, 225000, 12, 268800, 1050, 17384, 8);
const static SVoleParam svole_b11 =
    SVoleParam(10180608, 4971, 118000, 11, 178944, 699, 17384, 8);

template <typename P, typename IO> class SVole {
public:
  using K = typename P::K;
  using F = typename P::F;
  using AV = AuthValue<P>;
  using Bootstrap = typename P::template Bootstrap<IO>;

  IO *io;
  int party;
  SVoleParam param;
  int M;
  int ot_used, ot_limit;
  std::vector<AV> pre_auth;          // carry-over (size n_pre)
  std::vector<AV> vole_buf;          // current round (size n)

  FerretCOT *ferret = nullptr;
  Bootstrap   *base_svole = nullptr;
  BaseCot<IO> *base_cot   = nullptr;
  MpfssReg<P, IO> *mpfss  = nullptr;
  OTPre<IO>   *ot_pre     = nullptr;

  F Delta;
  LpnAmplifier<P, 10> *lpn = nullptr;

  SVole(int party, IO *io, FerretCOT *ferret,
        F delta = P::f_zero(),
        SVoleParam param = svole_b13)
      : io(io), party(party), param(param), Delta(delta), ferret(ferret) {
    base_cot = new BaseCot<IO>(3 - party, io, true);
    setup();
  }

  ~SVole() {
    delete lpn;
    delete base_svole;
    delete base_cot;
    delete mpfss;
    delete ot_pre;
  }

  F delta() {
    if (party == BOB) return Delta;
    error("No delta for ALICE");
    return P::f_zero();
  }

  void extend(AV *out, int num) {
    while (num > 0) {
      if (ot_used >= ot_limit) {
        extend_round();
        ot_used = 0;
      }
      int take = (int)std::min<int64_t>(num, (int64_t)ot_limit - ot_used);
      std::memcpy(out, vole_buf.data() + ot_used, take * sizeof(AV));
      out += take;
      num -= take;
      ot_used += take;
    }
  }

private:
  void extend_send(AV *out, AV *pre, int tt,
                   MpfssReg<P, IO> *mpfss, OTPre<IO> *ot_pre,
                   LpnAmplifier<P, 10> *lpn) {
    mpfss->recver_init();
    mpfss->mpfss(ot_pre, pre, out);
    lpn->compute_send(pre + tt, out);
  }

  void extend_recv(AV *out, AV *pre, int tt,
                   MpfssReg<P, IO> *mpfss, OTPre<IO> *ot_pre,
                   LpnAmplifier<P, 10> *lpn) {
    mpfss->sender_init(Delta);
    mpfss->mpfss(ot_pre, pre, out);
    lpn->compute_recv(pre + tt, out);
  }

  void extend_round() {
    base_cot->cot_gen(ot_pre, ot_pre->n);
    // Zero vole_buf so .val starts at zero (mpfss only writes .val at
    // sparse positions on the receiver side).
    std::memset(vole_buf.data(), 0, param.n * sizeof(AV));
    if (party == ALICE) {
      extend_send(vole_buf.data(), pre_auth.data(), param.t, mpfss, ot_pre, lpn);
    } else {
      extend_recv(vole_buf.data(), pre_auth.data(), param.t, mpfss, ot_pre, lpn);
    }
    std::memcpy(pre_auth.data(), vole_buf.data() + ot_limit, M * sizeof(AV));
  }

  void extend_initialization() {
    lpn = new LpnAmplifier<P, 10>(param.n, param.k);
    base_svole = new Bootstrap(party, io, ferret,
                               party == BOB ? Delta : P::f_zero());
    ot_pre = new OTPre<IO>(io, param.log_bin_sz, param.t);
    mpfss = new MpfssReg<P, IO>(3 - party, param.n, param.t, param.log_bin_sz, io);
    mpfss->set_malicious();
    ot_limit = param.buf_sz();
    M = param.n - ot_limit;
    ot_used = ot_limit;
  }

  void setup() {
    extend_initialization();

    if (party == ALICE) base_cot->cot_gen_pre();
    else                base_cot->cot_gen_pre(Delta);

    int M_pre = param.k_pre + param.t_pre + 1;
    pre_auth.assign(param.n_pre, AV{});
    std::vector<AV> pre_auth0(M_pre, AV{});

    LpnAmplifier<P, 10> lpn_pre(param.n_pre, param.k_pre);
    Bootstrap base_svole_pre(party, io, ferret,
                             party == BOB ? Delta : P::f_zero());
    OTPre<IO> ot_pre1(io, param.log_bin_sz_pre, param.t_pre);
    MpfssReg<P, IO> mpfss_pre(3 - party, param.n_pre, param.t_pre,
                              param.log_bin_sz_pre, io);
    mpfss_pre.set_malicious();

    base_cot->cot_gen(&ot_pre1, ot_pre1.n);

    base_svole_pre.extend(pre_auth0.data(), M_pre);

    if (party == ALICE)
      extend_send(pre_auth.data(), pre_auth0.data(), param.t_pre,
                  &mpfss_pre, &ot_pre1, &lpn_pre);
    else
      extend_recv(pre_auth.data(), pre_auth0.data(), param.t_pre,
                  &mpfss_pre, &ot_pre1, &lpn_pre);

    vole_buf.assign(param.n, AV{});
  }
};

} // namespace emp
#endif
