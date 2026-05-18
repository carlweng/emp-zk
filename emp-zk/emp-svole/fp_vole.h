#ifndef EMP_SVOLE_FP_VOLE_H__
#define EMP_SVOLE_FP_VOLE_H__

#include "emp-zk/emp-svole/base_cot.h"
#include "emp-zk/emp-svole/fp_base_svole.h"
#include "emp-zk/emp-svole/fp_lpn.h"
#include "emp-zk/emp-svole/fp_mpfss_reg.h"
#include "emp-zk/emp-svole/fp_policy.h"
#include "emp-zk/emp-svole/fp_utility.h"
#include "emp-zk/emp-svole/preot.h"

// FpVOLE<Policy, IO>: F_p sVOLE orchestrator.
//
// Three-layer pipeline:
//   1. Policy::Bootstrap<IO> — base sVOLE via COPE (Cope + Base_svole)
//   2. MpfssRegFp<IO>        — small sVOLE + GGM trees → t-sparse vector
//   3. LpnFp<10>             — t-sparse + carry-over → n pseudorandom pairs
//
// Internal buffers are AoS (Policy::AuthValue[]) — for MersennePolicy61
// the AuthValue bytes alias __uint128_t (mac-first), so the internal
// MpfssRegFp / LpnFp / FpSpfss code keeps operating on __uint128_t*
// via reinterpret_cast for SIMD.
//
// Note F_p party convention is inverted vs F2k (ALICE = Δ holder).
// Consumers in emp-zk-arith pass `3 - external_party` to flip labels.

namespace emp {

class SVoleFpParam {
public:
  int64_t n, t, k, log_bin_sz;
  int64_t n_pre, t_pre, k_pre, log_bin_sz_pre;

  SVoleFpParam() {}
  SVoleFpParam(int64_t n, int64_t t, int64_t k, int64_t log_bin_sz,
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

const static SVoleFpParam svole_fp_default =
    SVoleFpParam(10168320, 4965, 158000, 11, 166400, 2600, 5060, 6);

template <typename Policy = MersennePolicy61, typename IO = NetIO>
class FpVOLE {
public:
  using AuthValue = typename Policy::AuthValue;
  using F = typename Policy::F;
  using K = typename Policy::K;

  IO *io;
  int party;
  SVoleFpParam param;
  int64_t M;
  int64_t ot_used, ot_limit;
  std::vector<AuthValue> pre_yz;     // carry-over
  std::vector<AuthValue> vole_buf;   // current round's output

  BaseCot<IO> *cot;
  OTPre<IO> *pre_ot = nullptr;

  __uint128_t Delta;
  LpnFp<10> *lpn = nullptr;
  MpfssRegFp<IO> *mpfss = nullptr;

  FpVOLE(int party, IO *io, Ferret * /*ferret*/ = nullptr,
         F delta = Policy::f_zero(),
         SVoleFpParam param = svole_fp_default)
      : io(io), party(party), param(param), Delta(delta) {
    cot = new BaseCot<IO>(party, io, true);
    cot->cot_gen_pre();
    setup();
  }

  ~FpVOLE() {
    delete pre_ot;
    delete lpn;
    delete mpfss;
    delete cot;
  }

  F delta() {
    if (party == ALICE) return (F)Delta;
    error("No delta for BOB");
    return 0;
  }

  // Produce `num` fresh sVOLE pairs into `out`. Refills the internal
  // working buffer one round at a time as needed.
  void extend(AuthValue *out, int64_t num) {
    while (num > 0) {
      if (ot_used >= ot_limit) {
        extend_round();
        ot_used = 0;
      }
      int64_t take = std::min<int64_t>(num, ot_limit - ot_used);
      std::memcpy(out, vole_buf.data() + ot_used, take * sizeof(AuthValue));
      out += take;
      num -= take;
      ot_used += take;
    }
  }

  // Debug helper preserved for compatibility with vole_triple test.
  void check_triple(__uint128_t x, __uint128_t *y, int64_t size) {
    if (party == ALICE) {
      io->send_data(&x, sizeof(__uint128_t));
      io->send_data(y, size * sizeof(__uint128_t));
    } else {
      __uint128_t delta;
      std::vector<__uint128_t> k(size);
      io->recv_data(&delta, sizeof(__uint128_t));
      io->recv_data(k.data(), size * sizeof(__uint128_t));
      for (int64_t i = 0; i < size; ++i) {
        __uint128_t tmp = mod(delta * (y[i] >> 64), pr);
        tmp = mod(tmp + k[i], pr);
        if (tmp != (y[i] & 0xFFFFFFFFFFFFFFFFLL)) {
          std::cout << "triple error at index: " << i << std::endl;
          abort();
        }
      }
    }
  }

private:
  void extend_initialization() {
    lpn = new LpnFp<10>(param.n, param.k);
    mpfss = new MpfssRegFp<IO>(party, param.n, param.t, param.log_bin_sz, io);
    mpfss->set_malicious();

    pre_ot = new OTPre<IO>(io, mpfss->tree_height - 1, mpfss->tree_n);
    M = param.k + param.t + 1;
    ot_limit = param.n - M;
    ot_used = ot_limit;        // force first extend to refill
  }

  // Internal mpfss / lpn take __uint128_t* (packed val<<64|mac). Cast
  // from AuthValue* at the boundary — bytes match by Policy contract.
  void extend_send(AuthValue *y, AuthValue *key) {
    mpfss->sender_init(Delta);
    mpfss->mpfss(pre_ot, (__uint128_t *)key, (__uint128_t *)y);
    lpn->compute_send((__uint128_t *)y,
                      (__uint128_t *)(key + mpfss->tree_n + 1));
  }

  void extend_recv(AuthValue *z, AuthValue *mac) {
    mpfss->recver_init();
    mpfss->mpfss(pre_ot, (__uint128_t *)mac, (__uint128_t *)z);
    lpn->compute_recv((__uint128_t *)z,
                      (__uint128_t *)(mac + mpfss->tree_n + 1));
  }

  void extend_round() {
    cot->cot_gen(pre_ot, pre_ot->n);
    if (party == ALICE)
      extend_send(vole_buf.data(), pre_yz.data());
    else
      extend_recv(vole_buf.data(), pre_yz.data());
    std::memcpy(pre_yz.data(), vole_buf.data() + ot_limit,
                M * sizeof(AuthValue));
  }

  void setup() {
    extend_initialization();

    LpnFp<10> lpn_pre(param.n_pre, param.k_pre);
    MpfssRegFp<IO> mpfss_pre(party, param.n_pre, param.t_pre,
                             param.log_bin_sz_pre, io);
    mpfss_pre.set_malicious();
    OTPre<IO> pre_ot_ini(io, mpfss_pre.tree_height - 1, mpfss_pre.tree_n);

    int64_t M_pre = pre_ot_ini.n;
    cot->cot_gen(&pre_ot_ini, M_pre);

    int64_t triple_n = 1 + mpfss_pre.tree_n + param.k_pre;
    Base_svole<IO> *svole0;
    pre_yz.assign(param.n_pre, AuthValue{0, 0});
    std::vector<AuthValue> seed_pairs(triple_n);
    if (party == ALICE) {
      svole0 = new Base_svole<IO>(party, io, Delta);
      svole0->triple_gen_send((__uint128_t *)seed_pairs.data(), triple_n);
      mpfss_pre.sender_init(Delta);
      mpfss_pre.mpfss(&pre_ot_ini, (__uint128_t *)seed_pairs.data(),
                      (__uint128_t *)pre_yz.data());
      lpn_pre.compute_send((__uint128_t *)pre_yz.data(),
                           (__uint128_t *)(seed_pairs.data() + mpfss_pre.tree_n + 1));
    } else {
      svole0 = new Base_svole<IO>(party, io);
      svole0->triple_gen_recv((__uint128_t *)seed_pairs.data(), triple_n);
      mpfss_pre.recver_init();
      mpfss_pre.mpfss(&pre_ot_ini, (__uint128_t *)seed_pairs.data(),
                      (__uint128_t *)pre_yz.data());
      lpn_pre.compute_recv((__uint128_t *)pre_yz.data(),
                           (__uint128_t *)(seed_pairs.data() + mpfss_pre.tree_n + 1));
    }
    delete svole0;

    vole_buf.assign(param.n, AuthValue{0, 0});
  }
};

} // namespace emp
#endif
