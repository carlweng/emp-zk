#ifndef EMP_SVOLE_SPFSS_SENDER_H__
#define EMP_SVOLE_SPFSS_SENDER_H__

#include "emp-ot/ot_extension/cggm.h"
#include <emp-ot/emp-ot.h>
#include <emp-tool/emp-tool.h>

// Single-point FSS sender. Builds a depth-`d` Half-Tree cGGM tree from
// a random seed (cggm::build_sender), emits the 2(d-1) sibling-OT
// messages (K0, K1=Δ⊕K0 per level), and ships `secret_sum =
// ⊕leaves ⊕ gamma` so the receiver can recover its punctured leaf
// without learning Δ.
//
// `depth` is the caller's convention (= log_bin_sz + 1). cggm uses
// `cggm_d = depth - 1` as the number of expansion levels;
// 2^cggm_d = leave_n.

namespace emp {

template <typename IO> class SpfssSend {
public:
  block seed;
  block *ggm_tree;
  std::vector<block> m;
  block delta;
  block secret_sum;
  IO *io;
  int depth;
  int leave_n;
  PRG prg;

  SpfssSend(IO *io, int depth_in) : io(io), depth(depth_in) {
    this->leave_n = 1 << (depth_in - 1);
    m.resize((depth - 1) * 2);
    prg.random_block(&seed, 1);
  }

  void compute(block *ggm_tree_mem, block secret, block gamma) {
    this->delta = secret;
    this->ggm_tree = ggm_tree_mem;

    const int cggm_d = depth - 1;
    std::vector<block> K0(cggm_d);
    cggm::build_sender<cggm::kTile, /*ClearLeafLSB=*/false>(
        cggm_d, delta, seed, ggm_tree, K0.data());

    block *ot_msg_0 = m.data();
    block *ot_msg_1 = m.data() + cggm_d;
    for (int j = 0; j < cggm_d; ++j) {
      ot_msg_0[j] = K0[j];
      ot_msg_1[j] = delta ^ K0[j];
    }

    secret_sum = zero_block;
    for (int i = 0; i < leave_n; ++i)
      secret_sum ^= ggm_tree[i];
    secret_sum ^= gamma;
  }

  template <typename OT> void send(OT *ot, IO *io2, int s) {
    ot->send(m.data(), m.data() + (depth - 1), depth - 1, io2, s);
    io2->send_data(&secret_sum, sizeof(block));
    io2->flush();
  }

  void consistency_check_msg_gen(block &V, IO *io2) {
    block seed = io2->get_hash_block();
    std::vector<block> chi(leave_n);
    Hash hash;
    block digest = hash.hash_for_block(&seed, sizeof(block));
    uni_hash_coeff_gen(chi.data(), digest, leave_n);

    vector_inn_prdt_sum_red(&V, chi.data(), ggm_tree, leave_n);
  }
};
} // namespace emp
#endif
