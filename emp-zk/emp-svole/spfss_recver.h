#ifndef EMP_SVOLE_SPFSS_RECVER_H__
#define EMP_SVOLE_SPFSS_RECVER_H__

#include "emp-ot/ot_extension/cggm.h"
#include <emp-ot/emp-ot.h>
#include <emp-tool/emp-tool.h>

// Single-point FSS receiver. Mirrors SpfssSend: reconstructs the cGGM
// tree everywhere except the chosen `alpha = choice_pos` slot via
// cggm::eval_receiver, then recovers the punctured leaf from the
// sender's `share = secret_sum`.

namespace emp {

template <typename IO> class SpfssRecv {
public:
  block *ggm_tree;
  std::vector<block> m;
  std::unique_ptr<bool[]> b;
  IO *io;
  int choice_pos, depth, leave_n;
  block share;

  SpfssRecv(IO *io, int depth_in) : io(io), depth(depth_in) {
    this->leave_n = 1 << (depth_in - 1);
    m.resize(depth - 1);
    b.reset(new bool[depth - 1]);
  }

  // choice_pos == alpha (MSB-first encoding of NOT b[]).
  int get_index() {
    choice_pos = 0;
    for (int i = 0; i < depth - 1; ++i) {
      choice_pos <<= 1;
      if (!b[i])
        choice_pos += 1;
    }
    return choice_pos;
  }

  template <typename OT> void recv(OT *ot, IO *io2, int64_t s) {
    ot->recv(m.data(), b.get(), depth - 1, io2, s);
    io2->recv_data(&share, sizeof(block));
  }

  void compute(block *ggm_tree_mem, block delta2) {
    this->ggm_tree = ggm_tree_mem;
    const int cggm_d = depth - 1;
    cggm::eval_receiver<cggm::kTile, /*ClearLeafLSB=*/false>(
        cggm_d, choice_pos, m.data(), ggm_tree);

    // eval_receiver leaves ggm_tree[choice_pos] = zero_block; recover
    // the punctured leaf from the sender's secret_sum: the sender's
    // leaf at choice_pos = (XOR of reconstructed leaves) XOR share,
    // and the sparse-vector value is that XOR delta2.
    block nodes_sum = zero_block;
    for (int i = 0; i < leave_n; ++i)
      nodes_sum ^= ggm_tree[i];
    nodes_sum ^= share;
    ggm_tree[choice_pos] = delta2 ^ nodes_sum;
  }

  void consistency_check_msg_gen(block &chi_alpha, block &W, IO *io2) {
    block seed = io2->get_hash_block();
    std::vector<block> chi(leave_n);
    Hash hash;
    block digest = hash.hash_for_block(&seed, sizeof(block));
    uni_hash_coeff_gen(chi.data(), digest, leave_n);

    chi_alpha = chi[choice_pos];
    vector_inn_prdt_sum_red(&W, chi.data(), ggm_tree, leave_n);
  }
};
} // namespace emp
#endif
