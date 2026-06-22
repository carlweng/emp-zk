#ifndef ZK_FP_EXECUTION_H__
#define ZK_FP_EXECUTION_H__

#include "emp-ot/emp-ot.h"
#include "emp-zk/emp-zk-arith/ostriple.h"
#include "emp-zk/emp-zk-arith/edabit/edabits.h"

namespace emp {
using namespace std;

class ZKFpExec {
public:
  int64_t gid = 0;
  __uint128_t pub_mac;
  int B, c;

  static ZKFpExec *zk_exec;

  ZKFpExec() {
    // pub_mac is a public domain-separation tag from fixed-key PRP(0), reduced
    // into F_p. Prover and verifier use the same key so the tags match; it is
    // party-agnostic, so it is derived once here on the base.
    *(block *)&pub_mac = zero_block;
    PRP(zero_block).permute_block((block *)&pub_mac, 1);
    pub_mac = mod(pub_mac & (__uint128_t)0xFFFFFFFFFFFFFFFFULL, pr);
  }
  virtual ~ZKFpExec() {}

  virtual void feed(__uint128_t &label, const uint64_t &value) = 0;

  virtual void feed(__uint128_t *label, const uint64_t *value, int64_t len) = 0;

  virtual void reveal(__uint128_t *label, uint64_t *value, int64_t len) = 0;

  virtual void reveal_check(__uint128_t *label, const uint64_t *value,
                            int64_t len) = 0;

  virtual void reveal_check_zero(__uint128_t *label, int64_t len) = 0;

  virtual __uint128_t add_gate(const __uint128_t &a, const __uint128_t &b) = 0;

  virtual __uint128_t mul_gate(const __uint128_t &a, const __uint128_t &b) = 0;

  virtual __uint128_t mul_const_gate(const __uint128_t &a,
                                     const uint64_t &b) = 0;

  virtual __uint128_t pub_label(const uint64_t &a) = 0;
};

// ZKFpExec * ZKFpExec::zk_exec = nullptr;
}  // namespace emp

#endif
