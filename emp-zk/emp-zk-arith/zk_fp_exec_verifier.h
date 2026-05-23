#ifndef ZK_FP_EXECUTIION_VERIFIER_H__
#define ZK_FP_EXECUTIION_VERIFIER_H__
#include "emp-zk/emp-zk-arith/zk_fp_exec.h"

namespace emp {
using namespace std;

class ZKFpExecVer : public ZKFpExec {
public:
  FpOSTriple *ostriple;
  BoolIO *io = nullptr;
  __uint128_t delta;

  ZKFpExecVer(BoolIO *io) : ZKFpExec() {
    // pub_mac is a public domain-separation tag derived from fixed-key
    // AES — the output is known to both parties by design. Prover and
    // verifier use the same PRP key (PRP(0)) so the tags match.
    *(block *)&this->pub_mac = zero_block;
    PRP(zero_block).permute_block((block *)&this->pub_mac, 1);
    this->pub_mac = mod(this->pub_mac & (__uint128_t)0xFFFFFFFFFFFFFFFFULL, pr);
    this->io = io;
    this->ostriple = new FpOSTriple(BOB, io);
    this->delta = this->ostriple->delta;
  }

  ~ZKFpExecVer() { delete ostriple; }

  /*
   * Verifier is the sender in iterative COT
   * interface: get 1 authenticated bit
   * authenticated message, KEY
   */
  void feed(__uint128_t &label, const uint64_t &val) {
    label = this->ostriple->authenticated_val_input();
  }

  void feed(__uint128_t *label, const uint64_t *val, int64_t len) {
    this->ostriple->authenticated_val_input(label, len);
  }

  /*
   * check correctness of triples using cut and choose and bucketing
   * check correctness of the output
   */
  void reveal(__uint128_t *key, uint64_t *value, int64_t len) {
    this->ostriple->reveal_recv(key, value, len);
  }

  void reveal_check(__uint128_t *key, const uint64_t *value, int64_t len) {
    this->ostriple->reveal_check_recv(key, value, len);
  }

  void reveal_check_zero(__uint128_t *key, int64_t len) {
    this->ostriple->reveal_check_zero(key, len);
  }

  __uint128_t add_gate(const __uint128_t &a, const __uint128_t &b) {
    // val-first: BOB has val=0 in low, mac (K) in high. Sum the macs.
    uint64_t mac_a = (uint64_t)(a >> 64);
    uint64_t mac_b = (uint64_t)(b >> 64);
    uint64_t mac = add_mod(mac_a, mac_b);
    return ((__uint128_t)mac) << 64;
  }

  __uint128_t mul_gate(const __uint128_t &a, const __uint128_t &b) {
    ++this->gid;
    return ostriple->auth_compute_mul_recv(a, b);
  }

  __uint128_t mul_const_gate(const __uint128_t &a, const uint64_t &b) {
    return ostriple->auth_key_mul_const(a, b);
  }

  __uint128_t pub_label(const uint64_t &a) {
    uint64_t key = mult_mod(delta, a);
    key = PR - key;
    uint64_t mac = add_mod(key, (uint64_t)this->pub_mac);
    // val-first: mac in high 64, val=0 in low.
    return ((__uint128_t)mac) << 64;
  }
};
}  // namespace emp

#endif
