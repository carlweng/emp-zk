#ifndef EMP_SVOLE_F2K_MPFSS_H__
#define EMP_SVOLE_F2K_MPFSS_H__

#include "emp-zk/emp-svole/f2k_spfss.h"
#include "emp-zk/emp-svole/preot.h"
#include <emp-tool/emp-tool.h>
#include <set>

// F2k multi-point regular-syndrome FSS. Internal SoA: takes separate
// `K *triple_x` (val side, receiver only) and `F *triple_yz` (mac
// side, both parties); writes the sparse mac vector into `F* sparse`.
// Char-2-friendly (block-typed F + XOR / gfmul ops); F_p uses
// FpMpfssReg.
//
// Single-threaded.

namespace emp {

template <typename P, typename IO> class F2kMpfssReg {
public:
  using F = typename P::F;
  using K = typename P::K;

  int party;
  int64_t item_n, idx_max;
  int64_t tree_height, leave_n;
  int64_t tree_n;
  bool is_malicious;

  PRG prg;
  IO *netio;
  F secret_share_x;
  F **ggm_tree;
  std::vector<F> check_chialpha_buf, check_VW_buf;
  K *triple_x = nullptr;                 // val (receiver only)
  F *triple_yz = nullptr;                // mac (both)
  std::vector<uint32_t> item_pos_recver;

  F2kMpfssReg(int party, int64_t n, int64_t t, int64_t log_bin_sz, IO *io) {
    this->party = party;
    this->netio = io;
    this->is_malicious = false;

    this->item_n = t;
    this->idx_max = n;
    this->tree_height = log_bin_sz + 1;
    this->leave_n = 1 << log_bin_sz;
    this->tree_n = this->item_n;

    this->ggm_tree = (F **)malloc(this->item_n * sizeof(F *));

    if (party == BOB)
      check_chialpha_buf.resize(item_n);
    check_VW_buf.resize(item_n);
  }

  ~F2kMpfssReg() { free(ggm_tree); }

  void set_malicious() { is_malicious = true; }
  void sender_init(F delta) { secret_share_x = delta; }
  void recver_init() { item_pos_recver.resize(this->item_n); }

  void set_vec_x(K *out) {
    if (triple_x == nullptr || party == ALICE)
      error("mpfss: set value vector error");
    for (int64_t i = 0; i < tree_n; ++i) {
      int64_t pt = i * leave_n + (int64_t)item_pos_recver[i];
      out[pt] = P::k_add(out[pt], triple_x[i]);
    }
  }

  // receiver
  void mpfss(OTPre<IO> *ot, K *triple_x_in, F *triple_yz_in, F *sparse_vector) {
    this->triple_x = triple_x_in;
    this->triple_yz = triple_yz_in;
    mpfss(ot, sparse_vector);
  }

  // sender
  void mpfss(OTPre<IO> *ot, F *triple_yz_in, F *sparse_vector) {
    this->triple_yz = triple_yz_in;
    mpfss(ot, sparse_vector);
  }

  void mpfss(OTPre<IO> *ot, F *sparse_vector) {
    std::vector<F2kSpfssSend<IO> *> senders;
    std::vector<F2kSpfssRecv<IO> *> recvers;
    for (int64_t i = 0; i < tree_n; ++i) {
      if (party == ALICE) {
        senders.push_back(new F2kSpfssSend<IO>(netio, tree_height));
        ot->choices_sender();
      } else {
        recvers.push_back(new F2kSpfssRecv<IO>(netio, tree_height));
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
        if (is_malicious)
          senders[i]->consistency_check_msg_gen(check_VW_buf[i], netio);
        netio->flush();
      } else {
        recvers[i]->template recv<OTPre<IO>>(ot, netio, i);
        ggm_tree[i] = sparse_vector + i * leave_n;
        recvers[i]->compute(ggm_tree[i], triple_yz[i]);
        if (is_malicious)
          recvers[i]->consistency_check_msg_gen(
              check_chialpha_buf[i], check_VW_buf[i], netio);
        netio->flush();
      }
    }

    if (is_malicious) {
      if (party == ALICE)
        consistency_batch_check(triple_yz[tree_n], tree_n);
      else
        consistency_batch_check(triple_x, triple_yz[tree_n], tree_n);
    }

    for (auto p : senders) delete p;
    for (auto p : recvers) delete p;
  }

  // sender check
  void consistency_batch_check(F y, int64_t num) {
    F x_star;
    netio->recv_data(&x_star, sizeof(F));
    F vb = P::f_mul(secret_share_x, x_star);
    vb = P::f_sub(vb, y);

    for (int64_t i = 0; i < num; ++i)
      vb = P::f_add(vb, check_VW_buf[i]);
    Hash hash;
    block h = hash.hash_for_block(&vb, sizeof(F));
    netio->send_data(&h, sizeof(block));
    netio->flush();
  }

  // receiver check
  void consistency_batch_check(K *delta2, F z, int64_t num) {
    F beta_mul_chialpha = P::f_zero();
    for (int64_t i = 0; i < num; ++i) {
      F tmp = P::scalar_mul(delta2[i], check_chialpha_buf[i]);
      beta_mul_chialpha = P::f_add(beta_mul_chialpha, tmp);
    }
    F x_star = P::f_add(beta_mul_chialpha, P::embed(delta2[num]));
    netio->send_data(&x_star, sizeof(F));
    netio->flush();

    F va = z;
    for (int64_t i = 0; i < num; ++i)
      va = P::f_add(va, check_VW_buf[i]);

    Hash hash;
    block h = hash.hash_for_block(&va, sizeof(F));
    block r;
    netio->recv_data(&r, sizeof(block));
    if (!cmpBlock(&r, &h, 1))
      error("MPFSS batch check fails");
  }
};

} // namespace emp
#endif
