#ifndef EMP_SVOLE_FP_MPFSS_REG_H__
#define EMP_SVOLE_FP_MPFSS_REG_H__

#include "emp-zk/emp-svole/fp_spfss_recver.h"
#include "emp-zk/emp-svole/fp_spfss_sender.h"
#include "emp-zk/emp-svole/fp_utility.h"
#include "emp-zk/emp-svole/preot.h"
#include <emp-tool/emp-tool.h>
#include <set>

// F_p multi-point regular-syndrome FSS over __uint128_t leaves (one
// F_p element per leaf, with optional val packed into HIGH64 on the
// receiver side via set_vec_x). Each leaf-block is realized by an
// FpSpfss; OT preprocessing is shared via OTPre. Chi-fold consistency
// check uses mod-p arithmetic (uni_hash_coeff_gen / vector_inn_prdt_sum_red
// from fp_utility.h).
//
// Single-threaded (the old ThreadPool dispatch is gone).

namespace emp {

template <typename IO> class MpfssRegFp {
public:
  int party;
  int64_t item_n, idx_max, m;
  int64_t tree_height, leave_n;
  int64_t tree_n;
  bool is_malicious;

  PRG prg;
  IO *netio;
  __uint128_t secret_share_x;
  __uint128_t **ggm_tree;
  std::vector<__uint128_t> check_chialpha_buf, check_VW_buf;
  __uint128_t *triple_yz;
  std::vector<uint32_t> item_pos_recver;

  MpfssRegFp(int party, int64_t n, int64_t t, int64_t log_bin_sz, IO *io) {
    this->party = party;
    this->netio = io;
    this->is_malicious = false;

    // n = t * leave_n
    this->item_n = t;
    this->idx_max = n;
    this->tree_height = log_bin_sz + 1;
    this->leave_n = 1 << (this->tree_height - 1);
    this->tree_n = this->item_n;

    this->ggm_tree =
        (__uint128_t **)malloc(this->item_n * sizeof(__uint128_t *));

    if (party == BOB)
      check_chialpha_buf.resize(item_n);
    check_VW_buf.resize(item_n);
  }

  ~MpfssRegFp() { free(ggm_tree); }

  void set_malicious() { is_malicious = true; }

  void sender_init(__uint128_t delta) { secret_share_x = delta; }

  void recver_init() { item_pos_recver.resize(this->item_n); }

  void set_vec_x(__uint128_t *out, __uint128_t *in) {
    for (int64_t i = 0; i < tree_n; ++i) {
      int64_t pt = i * leave_n + ((int64_t)item_pos_recver[i] % leave_n);
      out[pt] = out[pt] ^ (__uint128_t)makeBlock(in[i], 0x0LL);
    }
  }

  // AuthValue<FpPolicy>* aliases __uint128_t* (mac-first layout); the
  // typed public API forwards to the existing __uint128_t-based code.
  void mpfss(OTPre<IO> *ot, AuthValue<FpPolicy> *triple_yz_auth,
             AuthValue<FpPolicy> *sparse_vector_auth) {
    this->triple_yz = (__uint128_t *)triple_yz_auth;
    mpfss(ot, (__uint128_t *)sparse_vector_auth);
  }

  void mpfss(OTPre<IO> *ot, __uint128_t *triple_yz,
             __uint128_t *sparse_vector) {
    this->triple_yz = triple_yz;
    mpfss(ot, sparse_vector);
  }

  void mpfss(OTPre<IO> *ot, __uint128_t *sparse_vector) {
    std::vector<FpSpfssSender<IO> *> senders;
    std::vector<FpSpfssRecver<IO> *> recvers;
    for (int64_t i = 0; i < tree_n; ++i) {
      if (party == ALICE) {
        senders.push_back(new FpSpfssSender<IO>(netio, tree_height));
        ot->choices_sender();
      } else {
        recvers.push_back(new FpSpfssRecver<IO>(netio, tree_height));
        ot->choices_recver(recvers[i]->b.get());
        item_pos_recver[i] = recvers[i]->get_index();
      }
    }
    netio->flush();
    ot->reset();

    for (int64_t i = 0; i < tree_n; ++i) {
      if (party == ALICE) {
        ggm_tree[i] = sparse_vector + i * leave_n;
        senders[i]->compute(ggm_tree[i], secret_share_x, triple_yz[i]);
        senders[i]->template send<OTPre<IO>>(ot, netio, i);
        netio->flush();
      } else {
        recvers[i]->template recv<OTPre<IO>>(ot, netio, i);
        ggm_tree[i] = sparse_vector + i * leave_n;
        recvers[i]->compute(ggm_tree[i], triple_yz[i]);
        netio->flush();
      }
    }

    if (is_malicious) {
      // Exchange a fresh shared seed for all per-tree chi-fold checks.
      // (Equivalent to the original seed_expand, single-threaded.)
      block check_seed = zero_block;
      if (party == ALICE) {
        netio->recv_data(&check_seed, sizeof(block));
      } else {
        prg.random_block(&check_seed, 1);
        netio->send_data(&check_seed, sizeof(block));
        netio->flush();
      }
      for (int64_t i = 0; i < tree_n; ++i) {
        if (party == ALICE)
          senders[i]->consistency_check_msg_gen(check_VW_buf[i], netio,
                                                check_seed);
        else
          recvers[i]->consistency_check_msg_gen(check_chialpha_buf[i],
                                                check_VW_buf[i], netio,
                                                triple_yz[i], check_seed);
      }
      netio->flush();
    }

    if (is_malicious) {
      if (party == ALICE)
        consistency_batch_check(triple_yz[tree_n], tree_n);
      else
        consistency_batch_check(triple_yz, triple_yz[tree_n], tree_n);
    }

    for (auto p : senders) delete p;
    for (auto p : recvers) delete p;
  }

  void consistency_batch_check(__uint128_t y, int64_t num) {
    uint64_t x_star;
    netio->recv_data(&x_star, sizeof(uint64_t));
    uint64_t tmp = mult_mod(secret_share_x, x_star);
    tmp = add_mod((uint64_t)y, tmp);
    uint64_t vb = pr - tmp; // y_star

    for (int64_t i = 0; i < num; ++i)
      vb = add_mod(vb, (uint64_t)check_VW_buf[i]);
    Hash hash;
    block h = hash.hash_for_block(&vb, sizeof(uint64_t));
    netio->send_data(&h, sizeof(block));
    netio->flush();
  }

  void consistency_batch_check(__uint128_t *delta2, __uint128_t z, int64_t num) {
    uint64_t beta_mul_chialpha = (uint64_t)0;
    for (int64_t i = 0; i < num; ++i) {
      uint64_t tmp = mult_mod(_mm_extract_epi64((block)delta2[i], 1),
                              check_chialpha_buf[i]);
      beta_mul_chialpha = add_mod(beta_mul_chialpha, tmp);
    }
    uint64_t x_star = PR - beta_mul_chialpha;
    x_star = add_mod(_mm_extract_epi64((block)z, 1), x_star);
    netio->send_data(&x_star, sizeof(uint64_t));
    netio->flush();

    uint64_t va = PR - _mm_extract_epi64((block)z, 0);
    for (int64_t i = 0; i < num; ++i)
      va = mod(va + check_VW_buf[i], pr);

    Hash hash;
    block h = hash.hash_for_block(&va, sizeof(uint64_t));
    block r;
    netio->recv_data(&r, sizeof(block));
    if (!cmpBlock(&r, &h, 1))
      error("MPFSS batch check fails");
  }
};

} // namespace emp
#endif
