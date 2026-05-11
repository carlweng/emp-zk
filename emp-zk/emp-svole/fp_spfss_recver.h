#ifndef EMP_SVOLE_FP_SPFSS_RECVER_H__
#define EMP_SVOLE_FP_SPFSS_RECVER_H__

#include "emp-ot/ot_extension/cggm.h"
#include "emp-zk/emp-svole/fp_utility.h"
#include <emp-ot/emp-ot.h>
#include <emp-tool/emp-tool.h>

// F_p single-point FSS receiver. Same Half-Tree cGGM reconstruction
// as SpfssRecv; leaves are reduced mod p before being folded into the
// F_p sparse vector.

namespace emp {

template <typename IO> class FpSpfssRecver {
public:
  block *ggm_tree;
  std::vector<block> m;
  __uint128_t *ggm_tree_int;
  std::unique_ptr<bool[]> b;
  int choice_pos, depth, leave_n;
  IO *io;
  uint64_t share;

  FpSpfssRecver(IO *io, int depth_in)
      : depth(depth_in), leave_n(1 << (depth_in - 1)), io(io) {
    m.resize(depth - 1);
    b.reset(new bool[depth - 1]);
  }

  int get_index() {
    choice_pos = 0;
    for (int i = 0; i < depth - 1; ++i) {
      choice_pos <<= 1;
      if (!b[i])
        choice_pos += 1;
    }
    return choice_pos;
  }

  template <typename OT> void recv(OT *ot, IO *io2, int s) {
    ot->recv(m.data(), b.get(), depth - 1, io2, s);
    io2->recv_data(&share, sizeof(uint64_t));
  }

  // delta2 only uses low 64 bits.
  void compute(__uint128_t *ggm_tree_mem, __uint128_t delta2) {
    ggm_tree_int = ggm_tree_mem;
    this->ggm_tree = (block *)ggm_tree_mem;

    const int cggm_d = depth - 1;
    cggm::eval_receiver<cggm::kTile, /*ClearLeafLSB=*/false>(
        cggm_d, choice_pos, m.data(), ggm_tree);

    // Reduce leaves to F_p and recover the punctured leaf from share.
    uint64_t nodes_sum = (uint64_t)0;
    for (int i = 0; i < leave_n; ++i) {
      extract_fp(ggm_tree_mem[i]);
      nodes_sum = add_mod(nodes_sum, (uint64_t)ggm_tree_mem[i]);
    }
    nodes_sum = add_mod(share, nodes_sum);
    nodes_sum = PR - nodes_sum;
    ggm_tree_mem[choice_pos] =
        add_mod(_mm_extract_epi64((block)delta2, 0), nodes_sum);
  }

  void consistency_check_msg_gen(__uint128_t &chi_alpha, __uint128_t &W,
                                 IO * /*io2*/, __uint128_t beta, block seed) {
    std::vector<__uint128_t> chi(leave_n);
    Hash hash;
    __uint128_t digest =
        mod(_mm_extract_epi64(hash.hash_for_block(&seed, sizeof(block)), 0));
    uni_hash_coeff_gen(chi.data(), digest, leave_n);

    chi_alpha = chi[choice_pos];

    // W = sum chi_i · w_i
    W = vector_inn_prdt_sum_red(chi.data(), (__uint128_t *)ggm_tree, leave_n);

    uint64_t tmp2 = _mm_extract_epi64((block)beta, 1);
    ggm_tree_int[choice_pos] =
        ((__uint128_t)tmp2 << 64) ^ ggm_tree_int[choice_pos];
  }
};

} // namespace emp
#endif
