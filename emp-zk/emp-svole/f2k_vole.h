#ifndef EMP_SVOLE_F2K_VOLE_H__
#define EMP_SVOLE_F2K_VOLE_H__

#include "emp-zk/emp-svole/base_cot.h"
#include "emp-zk/emp-svole/f2k_lpn.h"
#include "emp-zk/emp-svole/f2k_mpfss.h"
#include "emp-zk/emp-svole/f2k_policy.h"
#include "emp-zk/emp-svole/preot.h"

// F2kVOLE<Policy, IO>: F2k sVOLE orchestrator.
//
// Three-layer pipeline:
//   1. Policy::Bootstrap<IO>   — ferret COTs → small sVOLE (Galois packing)
//   2. F2kMpfssReg<Policy, IO> — small sVOLE + GGM trees → t-sparse vector
//   3. F2kLpnAmp<Policy, 10>   — t-sparse + carry-over → n pseudorandom pairs
//
// Internal buffers are SoA (separate K[] / F[]) so the LPN inner loops
// keep cache-line-tight random reads. Public API takes
// AuthValue[] (val,mac packed) and marshals at the extend() boundary.

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

template <typename Policy = F2kDefaultPolicy, typename IO = NetIO>
class F2kVOLE {
public:
  using AuthValue = typename Policy::AuthValue;
  using F = typename Policy::F;
  using K = typename Policy::K;
  using Bootstrap = typename Policy::template Bootstrap<IO>;

  IO *io;
  int party;
  SVoleParam param;
  int64_t M;
  int64_t ot_used, ot_limit;
  std::vector<F> pre_yz;
  std::vector<K> pre_x;
  std::vector<F> vole_yz;
  std::vector<K> vole_x;

  Ferret *ferret = nullptr;
  Bootstrap   *base_svole = nullptr;
  BaseCot<IO> *base_cot   = nullptr;
  F2kMpfssReg<Policy, IO> *mpfss = nullptr;
  OTPre<IO>   *ot_pre     = nullptr;

  F Delta;
  F2kLpnAmp<Policy, 10> *lpn = nullptr;

  F2kVOLE(int party, IO *io, Ferret *ferret,
          F delta = Policy::f_zero(),
          SVoleParam param = svole_b13)
      : io(io), party(party), param(param), Delta(delta), ferret(ferret) {
    base_cot = new BaseCot<IO>(3 - party, io, true);
    setup();
  }

  ~F2kVOLE() {
    delete lpn;
    delete base_svole;
    delete base_cot;
    delete mpfss;
    delete ot_pre;
  }

  F delta() {
    if (party == BOB) return Delta;
    error("No delta for ALICE");
    return Policy::f_zero();
  }

  void extend(AuthValue *out, int64_t num) {
    while (num > 0) {
      if (ot_used >= ot_limit) {
        extend_round();
        ot_used = 0;
      }
      int64_t take = std::min<int64_t>(num, ot_limit - ot_used);
      for (int64_t i = 0; i < take; ++i) {
        out[i].val = (party == ALICE) ? vole_x[ot_used + i] : Policy::k_zero();
        out[i].mac = vole_yz[ot_used + i];
      }
      out += take;
      num -= take;
      ot_used += take;
    }
  }

private:
  void extend_send(K *val, F *mac, K *pre_val, F *pre_mac, int64_t tt,
                   F2kMpfssReg<Policy, IO> *mp, OTPre<IO> *ot,
                   F2kLpnAmp<Policy, 10> *lp) {
    mp->recver_init();
    mp->mpfss(ot, pre_val, pre_mac, mac);
    mp->set_vec_x(val);
    lp->compute_send(pre_val + tt, val, pre_mac + tt, mac);
  }

  void extend_recv(F *mac, F *pre_mac, int64_t tt,
                   F2kMpfssReg<Policy, IO> *mp, OTPre<IO> *ot,
                   F2kLpnAmp<Policy, 10> *lp) {
    mp->sender_init(Delta);
    mp->mpfss(ot, pre_mac, mac);
    lp->compute_recv(pre_mac + tt, mac);
  }

  void extend_round() {
    base_cot->cot_gen(ot_pre, ot_pre->n);
    if (party == ALICE) {
      std::memset(vole_x.data(), 0, param.n * sizeof(K));
      extend_send(vole_x.data(), vole_yz.data(), pre_x.data(), pre_yz.data(),
                  param.t, mpfss, ot_pre, lpn);
      std::memcpy(pre_x.data(), vole_x.data() + ot_limit, M * sizeof(K));
    } else {
      extend_recv(vole_yz.data(), pre_yz.data(), param.t, mpfss, ot_pre, lpn);
    }
    std::memcpy(pre_yz.data(), vole_yz.data() + ot_limit, M * sizeof(F));
  }

  void extend_initialization() {
    lpn = new F2kLpnAmp<Policy, 10>(param.n, param.k);
    base_svole = new Bootstrap(party, io, ferret,
                               party == BOB ? Delta : Policy::f_zero());
    ot_pre = new OTPre<IO>(io, param.log_bin_sz, param.t);
    mpfss = new F2kMpfssReg<Policy, IO>(3 - party, param.n, param.t,
                                        param.log_bin_sz, io);
    mpfss->set_malicious();
    ot_limit = param.buf_sz();
    M = param.n - ot_limit;
    ot_used = ot_limit;
  }

  void setup() {
    extend_initialization();

    if (party == ALICE) base_cot->cot_gen_pre();
    else                base_cot->cot_gen_pre(Delta);

    int64_t M_pre = param.k_pre + param.t_pre + 1;
    pre_yz.assign(param.n_pre, Policy::f_zero());
    std::vector<F> pre_yz0(M_pre, Policy::f_zero());
    std::vector<K> pre_x0;
    if (party == ALICE) {
      pre_x.assign(param.n_pre, Policy::k_zero());
      pre_x0.assign(M_pre, Policy::k_zero());
    }

    F2kLpnAmp<Policy, 10> lpn_pre(param.n_pre, param.k_pre);
    Bootstrap base_svole_pre(party, io, ferret,
                             party == BOB ? Delta : Policy::f_zero());
    OTPre<IO> ot_pre1(io, param.log_bin_sz_pre, param.t_pre);
    F2kMpfssReg<Policy, IO> mpfss_pre(3 - party, param.n_pre, param.t_pre,
                                      param.log_bin_sz_pre, io);
    mpfss_pre.set_malicious();

    base_cot->cot_gen(&ot_pre1, ot_pre1.n);

    // Bootstrap M_pre raw sVOLE pairs into separate K[] and F[] arrays.
    base_svole_pre.extend(party == ALICE ? pre_x0.data() : nullptr,
                          pre_yz0.data(), M_pre);

    if (party == ALICE)
      extend_send(pre_x.data(), pre_yz.data(), pre_x0.data(), pre_yz0.data(),
                  param.t_pre, &mpfss_pre, &ot_pre1, &lpn_pre);
    else
      extend_recv(pre_yz.data(), pre_yz0.data(), param.t_pre, &mpfss_pre,
                  &ot_pre1, &lpn_pre);

    vole_yz.resize(param.n);
    if (party == ALICE) vole_x.resize(param.n);
  }
};

} // namespace emp
#endif
