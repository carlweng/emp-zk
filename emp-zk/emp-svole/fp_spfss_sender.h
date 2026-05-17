#ifndef EMP_SVOLE_FP_SPFSS_SENDER_H__
#define EMP_SVOLE_FP_SPFSS_SENDER_H__

#include "emp-ot/ot_extension/cggm.h"
#include "emp-zk/emp-svole/fp_utility.h"
#include <emp-ot/emp-ot.h>
#include <emp-tool/emp-tool.h>

// F_p single-point FSS sender. Same Half-Tree cGGM core as the char-2
// SpfssSend; leaves are reinterpreted as __uint128_t and reduced mod p
// (extract_fp) so the share/leaf-sum live in F_p rather than F_{2^128}.

namespace emp {

template <typename IO> class FpSpfssSender {
public:
  block seed;
  block *ggm_tree;
  std::vector<block> m;
  __uint128_t delta;
  uint64_t secret_sum;
  IO *io;
  int depth;
  int leave_n;
  PRG prg;

  FpSpfssSender(IO *io, int depth_in) : io(io), depth(depth_in) {
    this->leave_n = 1 << (this->depth - 1);
    m.resize((depth - 1) * 2);
    prg.random_block(&seed, 1);
  }

  void compute(__uint128_t *ggm_tree_mem, __uint128_t secret,
               __uint128_t gamma) {
    this->delta = secret;
    block *leaves_b = (block *)ggm_tree_mem;
    this->ggm_tree = leaves_b;
    block delta_b = (block)secret;

    const int cggm_d = depth - 1;
    std::vector<block> K0(cggm_d);
    cggm::build_sender<cggm::kTile, /*ClearLeafLSB=*/false>(
        cggm_d, delta_b, seed, leaves_b, K0.data());

    block *ot_msg_0 = m.data();
    block *ot_msg_1 = m.data() + cggm_d;
    for (int j = 0; j < cggm_d; ++j) {
      ot_msg_0[j] = K0[j];
      ot_msg_1[j] = delta_b ^ K0[j];
    }

    secret_sum = (uint64_t)0;
    for (int i = 0; i < leave_n; ++i) {
      extract_fp(ggm_tree_mem[i]);
      secret_sum = add_mod(secret_sum, (uint64_t)ggm_tree_mem[i]);
    }
    secret_sum = PR - secret_sum;
    secret_sum = add_mod((uint64_t)gamma, secret_sum);
  }

  template <typename OT> void send(OT *ot, IO *io2, int64_t s) {
    ot->send(m.data(), m.data() + (depth - 1), depth - 1, io2, s);
    io2->send_data(&secret_sum, sizeof(uint64_t));
    io2->flush();
  }

  void consistency_check_msg_gen(__uint128_t &V, IO * /*io2*/, block seed) {
    std::vector<__uint128_t> chi(leave_n);
    Hash hash;
    __uint128_t digest =
        mod(_mm_extract_epi64(hash.hash_for_block(&seed, sizeof(block)), 0));
    uni_hash_coeff_gen(chi.data(), digest, leave_n);

    V = vector_inn_prdt_sum_red(chi.data(), (__uint128_t *)ggm_tree, leave_n);
  }
};

} // namespace emp
#endif
