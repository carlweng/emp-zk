#ifndef EMP_SVOLE_FP_POLICY_H__
#define EMP_SVOLE_FP_POLICY_H__

#include "emp-zk/emp-svole/base_cot.h"
#include "emp-zk/emp-svole/field_policy.h"
#include "emp-zk/emp-svole/fp_base_svole.h"
#include "emp-zk/emp-svole/fp_utility.h"
#include "emp-zk/emp-svole/preot.h"

// F_p ⊂ F_p (degenerate "subfield = extension"): the prime-field
// instantiation of the unified sVOLE. K and F are both uint64_t
// (Mersenne p = 2^61 − 1). The OT-to-sVOLE bootstrap is COPE-essential
// (bit-decompose Δ, exchange tau corrections per element); afterwards
// the small→large amplification is MPFSS + LPN over F_p with mod-p
// arithmetic.
//
// AuthValue<FpPolicy> uses a mac-first layout (mac, val) so the bytes
// alias 1:1 with the historical (val << 64) | mac packing in
// __uint128_t. Internal F_p machinery still operates on __uint128_t*
// buffers via reinterpret_cast; downstream consumers see the named
// (val, mac) fields.

namespace emp {

struct FpPolicy;

// AuthValue<FpPolicy>: mac-first so bytes match `(val << 64) | mac`.
template <>
struct AuthValue<FpPolicy> {
  uint64_t mac;
  uint64_t val;
};

struct FpPolicy {
  using K = uint64_t;
  using F = uint64_t;

  // F ops (Mersenne arithmetic, defined in fp_utility.h)
  static inline F    f_zero()              { return 0; }
  static inline F    f_add (F a, F b)      { return add_mod(a, b); }
  static inline F    f_sub (F a, F b)      { return a >= b ? a - b : a + PR - b; }
  static inline F    f_mul (F a, F b)      { return mult_mod(a, b); }
  static inline bool f_eq  (F a, F b)      { return a == b; }

  static inline F    embed     (K x)       { return x; }
  static inline F    scalar_mul(K x, F y)  { return mult_mod(x, y); }

  static inline K    k_zero()              { return 0; }
  static inline K    k_add (K a, K b)      { return add_mod(a, b); }

  // F_p OT→sVOLE bootstrap: wraps Base_svole (COPE-essential).
  // Bytes of AuthValue<FpPolicy> match `(val << 64) | mac` packing in
  // __uint128_t, so Base_svole::triple_gen_send/recv writes directly
  // into the AuthValue buffer via reinterpret_cast.
  template <typename IO> class Bootstrap {
   public:
    int party;
    IO *io;
    F Delta;
    Bootstrap(int party, IO *io, FerretCOT * /*ferret*/, F delta = 0)
        : party(party), io(io), Delta(delta) {}

    void extend(AuthValue<FpPolicy> *out, int64_t num) {
      Base_svole<IO> bv = (party == ALICE)
          ? Base_svole<IO>(party, io, (__uint128_t)Delta)
          : Base_svole<IO>(party, io);
      __uint128_t *buf = (__uint128_t *)out;
      if (party == ALICE)
        bv.triple_gen_send(buf, num);
      else
        bv.triple_gen_recv(buf, num);
    }
  };
};

} // namespace emp

// fp_lpn.h / fp_mpfss_reg.h use AuthValue<FpPolicy> in their public
// signatures; include them after FpPolicy + the specialization above.
#include "emp-zk/emp-svole/fp_lpn.h"
#include "emp-zk/emp-svole/fp_mpfss_reg.h"

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

// SVole<P, IO> primary template specialized for FpPolicy. F_p stays on
// __uint128_t* internal buffers (matches MpfssRegFp / LpnFp signatures
// which manually pack the val/mac pair into a __uint128_t for SIMD).
template <typename P, typename IO> class SVole;

template <typename IO> class SVole<FpPolicy, IO> {
public:
  using K = FpPolicy::K;
  using F = FpPolicy::F;

  IO *io;
  int party;
  SVoleFpParam param;
  int64_t M;
  int64_t ot_used, ot_limit;
  std::vector<AuthValue<FpPolicy>> pre_yz;     // carry-over
  std::vector<AuthValue<FpPolicy>> vole_buf;   // current round's output

  BaseCot<IO> *cot;
  OTPre<IO> *pre_ot = nullptr;

  __uint128_t Delta;
  LpnFp<10> *lpn = nullptr;
  MpfssRegFp<IO> *mpfss = nullptr;

  // F_p convention (inverted vs F2k): ALICE holds Δ. Callers in
  // emp-zk-arith pass `3 - external_party` to flip the labels at
  // construction.
  SVole(int party, IO *io, FerretCOT * /*ferret*/ = nullptr,
        F delta = 0,
        SVoleFpParam param = svole_fp_default)
      : io(io), party(party), param(param), Delta(delta) {
    cot = new BaseCot<IO>(party, io, true);
    cot->cot_gen_pre();
    setup();
  }

  ~SVole() {
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
  void extend(AuthValue<FpPolicy> *out, int64_t num) {
    while (num > 0) {
      if (ot_used >= ot_limit) {
        extend_round();
        ot_used = 0;
      }
      int64_t take = std::min<int64_t>(num, ot_limit - ot_used);
      std::memcpy(out, vole_buf.data() + ot_used,
                  take * sizeof(AuthValue<FpPolicy>));
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

  void extend_send(AuthValue<FpPolicy> *y, MpfssRegFp<IO> *mpfss,
                   OTPre<IO> *pre_ot, LpnFp<10> *lpn,
                   AuthValue<FpPolicy> *key) {
    mpfss->sender_init(Delta);
    mpfss->mpfss(pre_ot, key, y);
    lpn->compute_send(y, key + mpfss->tree_n + 1);
  }

  void extend_recv(AuthValue<FpPolicy> *z, MpfssRegFp<IO> *mpfss,
                   OTPre<IO> *pre_ot, LpnFp<10> *lpn,
                   AuthValue<FpPolicy> *mac) {
    mpfss->recver_init();
    mpfss->mpfss(pre_ot, mac, z);
    lpn->compute_recv(z, mac + mpfss->tree_n + 1);
  }

  void extend_round() {
    cot->cot_gen(pre_ot, pre_ot->n);
    if (party == ALICE)
      extend_send(vole_buf.data(), mpfss, pre_ot, lpn, pre_yz.data());
    else
      extend_recv(vole_buf.data(), mpfss, pre_ot, lpn, pre_yz.data());
    std::memcpy(pre_yz.data(), vole_buf.data() + ot_limit,
                M * sizeof(AuthValue<FpPolicy>));
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
    pre_yz.assign(param.n_pre, AuthValue<FpPolicy>{0, 0});
    std::vector<AuthValue<FpPolicy>> seed_pairs(triple_n);
    if (party == ALICE) {
      svole0 = new Base_svole<IO>(party, io, Delta);
      svole0->triple_gen_send((__uint128_t *)seed_pairs.data(), triple_n);
      extend_send(pre_yz.data(), &mpfss_pre, &pre_ot_ini, &lpn_pre,
                  seed_pairs.data());
    } else {
      svole0 = new Base_svole<IO>(party, io);
      svole0->triple_gen_recv((__uint128_t *)seed_pairs.data(), triple_n);
      extend_recv(pre_yz.data(), &mpfss_pre, &pre_ot_ini, &lpn_pre,
                  seed_pairs.data());
    }
    delete svole0;

    vole_buf.assign(param.n, AuthValue<FpPolicy>{0, 0});
  }
};

} // namespace emp
#endif
