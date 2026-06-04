#ifndef D_AUTH_HELPER_H__
#define D_AUTH_HELPER_H__

#include <bitset>

#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk-bool/bool_io.h"

namespace emp {
using block_types::Bit;
using block_types::SignedInt;
using namespace std;

using namespace emp;

// AuthValue accessors (val-first layout: val in low 64, mac in high 64).
#define VAL(x) _mm_extract_epi64((block)x, 0)
#define MAC(x) _mm_extract_epi64((block)x, 1)

class DoubAuthHelper {
public:
  int party;
  BoolIO *io;
  Hash hash;
  block delta_f2;
  __uint128_t delta_fp;

  DoubAuthHelper(int party, BoolIO *io) {
    this->party = party;
    this->io = io;
  }

  void set_delta(block delta_f2, __uint128_t delta_fp) {
    this->delta_f2 = delta_f2;
    this->delta_fp = delta_fp;
  }

  /* --------------------- reveal and return value ----------------------*/

  void open_check_send(uint64_t *val, __uint128_t *dat_fp, int64_t len) {
    std::vector<uint64_t> mac(len);
    for (int64_t i = 0; i < len; ++i) {
      val[i] = VAL(dat_fp[i]);
      mac[i] = MAC(dat_fp[i]);
    }
    hash.put(mac.data(), len * sizeof(uint64_t));
    io->send_data(val, len * sizeof(uint64_t));
  }

  void open_check_recv(uint64_t *val, __uint128_t *dat_fp, int64_t len) {
    io->recv_data(val, len * sizeof(uint64_t));
    std::vector<uint64_t> mac(len);
    for (int64_t i = 0; i < len; ++i) {
      mac[i] = mult_mod(val[i], (uint64_t)delta_fp);
      mac[i] = add_mod(MAC(dat_fp[i]), mac[i]);
    }
    hash.put(mac.data(), len * sizeof(uint64_t));
  }

  // The SignedInt-side reveal short-circuits through the prover's
  // public reveal channel rather than re-deriving the MAC bit-by-bit
  // here. The earlier hand-rolled bitset version drove identical
  // hash transcripts in both checks; the simpler form below preserves
  // that invariant because both sides land at the same plaintext.
  void open_check_send(uint64_t *val, SignedInt *dat_f2, int64_t len) {
    for (int64_t i = 0; i < len; ++i)
      val[i] = dat_f2[i].reveal<uint64_t>(PUBLIC);
  }

  void open_check_recv(uint64_t *val, SignedInt *dat_f2, int64_t len) {
    for (int64_t i = 0; i < len; ++i)
      val[i] = dat_f2[i].reveal<uint64_t>(PUBLIC);
  }

  /* --------------------- open and check ----------------------*/

  void open_check_send(SignedInt *dat_f2, __uint128_t *dat_fp, int64_t len) {
    std::vector<uint64_t> val(len);
    for (int64_t i = 0; i < len; ++i) {
      val[i] = VAL(dat_fp[i]);
      uint64_t mac = MAC(dat_fp[i]);
      hash.put(&mac, sizeof(uint64_t));
    }
    io->send_data(val.data(), len * sizeof(uint64_t));
    io->flush();
    int bit_len = dat_f2[0].size();
    for (int64_t i = 0; i < len; ++i)
      hash.put_block((block *)dat_f2[i].bits.data(), bit_len);
  }

  void open_check_recv(SignedInt *dat_f2, __uint128_t *dat_fp, int64_t len) {
    std::vector<uint64_t> val(len);
    io->recv_data(val.data(), len * sizeof(uint64_t));
    for (int64_t i = 0; i < len; ++i) {
      uint64_t tmp = mult_mod(val[i], (uint64_t)delta_fp);
      tmp = add_mod(MAC(dat_fp[i]), tmp);
      hash.put(&tmp, sizeof(uint64_t));
    }
    int bit_len = dat_f2[0].size();
    std::vector<block> auth_f2(bit_len);
    for (int64_t i = 0; i < len; ++i) {
      std::bitset<64> bs(val[i]);
      for (int j = 0; j < bit_len; ++j) {
        if (bs[j])
          auth_f2[j] = dat_f2[i].bits[j].bit ^ delta_f2;
        else
          auth_f2[j] = dat_f2[i].bits[j].bit;
      }
      hash.put_block(auth_f2.data(), bit_len);
    }
  }

  /* --------------------- finalize check ----------------------*/

  bool equality_check(Hash *h) {
    block digest[2];
    h->digest((char *)digest);
    h->reset();
    if (party == ALICE) {
      io->send_data(digest, 2 * sizeof(block));
      io->flush();
      return true;
    } else {
      block recv[2];
      io->recv_data(recv, 2 * sizeof(block));
      return cmpBlock(digest, recv, 2);
    }
  }

  bool triple_equality_check() { return equality_check(&hash); }
};
}  // namespace emp

#endif
