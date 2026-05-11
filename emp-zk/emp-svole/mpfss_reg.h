#ifndef EMP_SVOLE_MPFSS_REG_H__
#define EMP_SVOLE_MPFSS_REG_H__

#include "emp-zk/emp-svole/field_policy.h"
#include "emp-zk/emp-svole/spfss_recver.h"
#include "emp-zk/emp-svole/spfss_sender.h"
#include "emp-zk/emp-svole/preot.h"
#include <emp-tool/emp-tool.h>
#include <set>

// Multi-point regular-syndrome FSS over `AuthValue<P>[]`. The cGGM
// trees produce block leaves into a scratch mac buffer; after each
// tree, the .mac of the matching `AuthValue` is filled. The receiver-
// side mpfss also writes .val at the sparse positions, using the
// caller-provided `pre[i].val`.
//
// Single-threaded. Char-2-friendly (block-typed F + XOR / gfmul ops);
// F_p uses MpfssRegFp instead.

namespace emp {

template <typename P, typename IO> class MpfssReg {
public:
  using F = typename P::F;
  using K = typename P::K;

  int party;
  int item_n, idx_max;
  int tree_height, leave_n;
  int tree_n;
  bool is_malicious;

  PRG prg;
  IO *netio;
  F secret_share_x;
  block **ggm_tree;
  std::vector<F> check_chialpha_buf, check_VW_buf;
  std::vector<block> mac_buf;          // scratch for cggm leaves
  std::vector<uint32_t> item_pos_recver;

  MpfssReg(int party, int n, int t, int log_bin_sz, IO *io) {
    this->party = party;
    this->netio = io;
    this->is_malicious = false;

    this->item_n = t;
    this->idx_max = n;
    this->tree_height = log_bin_sz + 1;
    this->leave_n = 1 << log_bin_sz;
    this->tree_n = this->item_n;

    this->ggm_tree = (block **)malloc(this->item_n * sizeof(block *));
    mac_buf.resize(n);

    if (party == BOB)
      check_chialpha_buf.resize(item_n);
    check_VW_buf.resize(item_n);
  }

  ~MpfssReg() { free(ggm_tree); }

  void set_malicious() { is_malicious = true; }
  void sender_init(F delta) { secret_share_x = delta; }
  void recver_init() { item_pos_recver.resize(this->item_n); }

  // Both sides take `pre` (AuthValue<P>*); the sender reads pre[i].mac
  // only, the receiver reads pre[i].val (for the sparse-position
  // injection and the malicious chi-fold) and pre[i].mac.
  void mpfss(OTPre<IO> *ot, AuthValue<P> *pre, AuthValue<P> *sparse_vector) {
    std::vector<SpfssSend<IO> *> senders;
    std::vector<SpfssRecv<IO> *> recvers;
    for (int i = 0; i < tree_n; ++i) {
      if (party == ALICE) {
        senders.push_back(new SpfssSend<IO>(netio, tree_height));
        ot->choices_sender();
      } else {
        recvers.push_back(new SpfssRecv<IO>(netio, tree_height));
        ot->choices_recver(recvers[i]->b.get());
        item_pos_recver[i] = recvers[i]->get_index();
      }
    }
    netio->flush();
    ot->reset();

    for (int i = 0; i < tree_n; ++i) {
      block *leaves_i = mac_buf.data() + i * leave_n;
      ggm_tree[i] = leaves_i;
      if (party == ALICE) {
        senders[i]->compute(leaves_i, secret_share_x, pre[i].mac);
        senders[i]->template send<OTPre<IO>>(ot, netio, i);
        if (is_malicious)
          senders[i]->consistency_check_msg_gen(check_VW_buf[i], netio);
        netio->flush();
      } else {
        recvers[i]->template recv<OTPre<IO>>(ot, netio, i);
        recvers[i]->compute(leaves_i, pre[i].mac);
        if (is_malicious)
          recvers[i]->consistency_check_msg_gen(
              check_chialpha_buf[i], check_VW_buf[i], netio);
        netio->flush();
      }
    }

    if (is_malicious) {
      if (party == ALICE)
        consistency_batch_check(pre[tree_n].mac, tree_n);
      else
        consistency_batch_check(pre, pre[tree_n].mac, tree_n);
    }

    // Copy the scratch mac buffer into the AuthValue array's .mac slots.
    for (int i = 0; i < idx_max; ++i)
      sparse_vector[i].mac = mac_buf[i];

    // Receiver injects val at sparse positions.
    if (party == BOB) {
      for (int i = 0; i < tree_n; ++i) {
        int64_t pt = (int64_t)i * leave_n + (int64_t)item_pos_recver[i];
        sparse_vector[pt].val = P::k_add(sparse_vector[pt].val, pre[i].val);
      }
    }

    for (auto p : senders) delete p;
    for (auto p : recvers) delete p;
  }

  // sender check
  void consistency_batch_check(F y, int num) {
    F x_star;
    netio->recv_data(&x_star, sizeof(F));
    F vb = P::f_mul(secret_share_x, x_star);
    vb = P::f_sub(vb, y);

    for (int i = 0; i < num; ++i)
      vb = P::f_add(vb, check_VW_buf[i]);
    Hash hash;
    block h = hash.hash_for_block(&vb, sizeof(F));
    netio->send_data(&h, sizeof(block));
    netio->flush();
  }

  // receiver check
  void consistency_batch_check(AuthValue<P> *pre, F z, int num) {
    F beta_mul_chialpha = P::f_zero();
    for (int i = 0; i < num; ++i) {
      F tmp = P::scalar_mul(pre[i].val, check_chialpha_buf[i]);
      beta_mul_chialpha = P::f_add(beta_mul_chialpha, tmp);
    }
    F x_star = P::f_add(beta_mul_chialpha, P::embed(pre[num].val));
    netio->send_data(&x_star, sizeof(F));
    netio->flush();

    F va = z;
    for (int i = 0; i < num; ++i)
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
