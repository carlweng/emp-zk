#ifndef OS_TRIPLE_H__
#define OS_TRIPLE_H__

#include "emp-ot/emp-ot.h"
#include "emp-zk/emp-zk-bool/bool_io.h"
#include "emp-zk/emp-zk-bool/cheat_record.h"

namespace emp {

class OSTriple {
public:
  static constexpr int64_t CHECK_SZ = 1024 * 1024;

  int party, threads;
  block delta;

  int check_cnt = 0;
  block *andgate_out_buffer = nullptr;
  block *andgate_left_buffer = nullptr;
  block *andgate_right_buffer = nullptr;

  GaloisFieldPacking pack;

  BoolIO *io;
  BoolIO **ios;
  PRG prg;
  FerretCOT *ferret = nullptr;
  ThreadPool *pool = nullptr;

  // Output-MAC accumulator (formerly the separate TripleAuth helper).
  // Folded in because OSTriple already owns delta + io and the helper
  // was a thin Hash wrapper using the same delta-based xor.
  Hash auth_hash;
  vector<block> auth_tmp;

  OSTriple(int party, int threads, BoolIO **ios)
      : party(party), threads(threads) {
    // FerretCOT takes IOChannel**; BoolIO is a single-inheritance public
    // subclass with the IOChannel subobject at offset 0, so the cast is
    // a no-op at runtime.
    IOChannel **iochan_ios = reinterpret_cast<IOChannel **>(ios);
    ferret = new FerretCOT(3 - party, threads, iochan_ios, true);
    delta = ferret->Delta;
    io = ios[0];
    this->ios = ios;
    pool = new ThreadPool(threads);

    andgate_out_buffer = new block[CHECK_SZ];
    andgate_left_buffer = new block[CHECK_SZ];
    andgate_right_buffer = new block[CHECK_SZ];

    block tmp;
    ferret->rcot_send(&tmp, 1);
  }

  ~OSTriple() {
    if (check_cnt != 0)
      andgate_correctness_check_manage();
    if (!finalize_macs())
      CheatRecord::put("emp-zk-bool finalize");
    delete ferret;
    delete[] andgate_out_buffer;
    delete[] andgate_left_buffer;
    delete[] andgate_right_buffer;
    delete pool;
  }

  uint64_t communication() {
    uint64_t res = 0;
    for (int i = 0; i < threads; ++i)
      res += ios[i]->counter;
    return res;
  }

  /* ---------------------helper bit ops----------------------*/

  // The authenticated-bit format keeps the cleartext bit in the LSB
  // and the MAC in the upper 127 bits. clear_lsb / with_lsb / xor_delta_if
  // express that as named ops rather than ad-hoc choice[]/minusone tricks.
  static block clear_lsb(block b) {
    return b & makeBlock(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFEULL);
  }
  static block with_lsb(block b, bool v) {
    return clear_lsb(b) ^ makeBlock(0, v ? 1 : 0);
  }
  block xor_delta_if(block b, bool cond) const {
    return cond ? (b ^ delta) : b;
  }

  /* ---------------------inputs----------------------*/
  /*
   * authenticated bits for inputs of the prover
   */
  void authenticated_bits_input(block *auth, const bool *in, int len) {
    ferret->rcot_send(auth, len);

    if (party == ALICE) {
      for (int i = 0; i < len; ++i) {
        bool buff = getLSB(auth[i]) ^ in[i];
        auth[i] = with_lsb(auth[i], in[i]);
        io->send_bit(buff);
      }
    } else {
      for (int i = 0; i < len; ++i) {
        bool buff = io->recv_bit();
        auth[i] = clear_lsb(xor_delta_if(auth[i], buff));
      }
    }
  }

  /*
   * authenticated bits for computing AND gates
   */
  block auth_compute_and(block a, block b) {
    block auth;
    if (check_cnt == CHECK_SZ) {
      andgate_correctness_check_manage();
      check_cnt = 0;
    }

    ferret->rcot_send(&auth, 1);
    andgate_left_buffer[check_cnt] = a;
    andgate_right_buffer[check_cnt] = b;

    if (party == ALICE) {
      bool s = getLSB(a) and getLSB(b);
      bool d = s ^ getLSB(auth);
      auth = with_lsb(auth, s);
      io->send_bit(d);
    } else {
      bool d = io->recv_bit();
      auth = clear_lsb(xor_delta_if(auth, d));
    }
    andgate_out_buffer[check_cnt] = auth;
    check_cnt++;
    return auth;
  }

  /* ---------------------check----------------------*/

  void andgate_correctness_check_manage() {
    io->flush();
    block seed = io->get_hash_block();
    std::vector<std::future<void>> fut;

    int share_seed_n = threads;
    block *share_seed = new block[share_seed_n];
    PRG(&seed).random_block(share_seed, share_seed_n);

    // Distribute check_cnt tasks across `threads` workers. Workers
    // 0..threads-2 each handle task_base; the last takes whatever is
    // left. The leftover formula must be defined when task_base == 0
    // (i.e., check_cnt < threads), so we compute it as a subtraction
    // rather than the prior `task_base + check_cnt % task_base` form.
    uint32_t task_base = check_cnt / threads;
    uint32_t leftover = check_cnt - task_base * (threads - 1);
    uint32_t start = 0;
    block *sum = new block[2 * threads];
    for (int i = 0; i < threads - 1; ++i) {
      fut.push_back(
          pool->enqueue([this, sum, i, start, task_base, share_seed]() {
            andgate_correctness_check(sum, i, start, task_base, share_seed[i]);
          }));
      start += task_base;
    }
    andgate_correctness_check(sum, threads - 1, start, leftover,
                              share_seed[threads - 1]);

    for (auto &f : fut)
      f.get();

    if (party == ALICE) {
      block ope_data[128];
      ferret->rcot_send(ope_data, 128);
      uint64_t ch_bits[2];
      for (int i = 0; i < 2; ++i) {
        if (getLSB(ope_data[64 * i + 63]))
          ch_bits[i] = 1;
        else
          ch_bits[i] = 0;
        for (int j = 62; j >= 0; --j) {
          ch_bits[i] <<= 1;
          if (getLSB(ope_data[64 * i + j]))
            ch_bits[i]++;
        }
      }
      block A_star[2];
      A_star[1] = makeBlock(ch_bits[1], ch_bits[0]);
      pack.packing(A_star, ope_data);
      for (int i = 0; i < threads; ++i) {
        A_star[0] = A_star[0] ^ sum[2 * i];
        A_star[1] = A_star[1] ^ sum[2 * i + 1];
      }
      io->send_data(A_star, 2 * sizeof(block));
    } else {
      block ope_data[128];
      ferret->rcot_send(ope_data, 128);
      block B_star;
      pack.packing(&B_star, ope_data);
      for (int i = 0; i < threads; ++i)
        B_star = B_star ^ sum[i];
      block A_star[2];
      io->recv_data(A_star, 2 * sizeof(block));
      block W;
      gfmul(A_star[1], this->delta, &W);
      W = W ^ A_star[0];
      if (cmpBlock(&W, &B_star, 1) != 1)
        CheatRecord::put("emp_zk_bool AND batch check");
    }
    io->flush();
    delete[] share_seed;
    delete[] sum;
  }

  void andgate_correctness_check(block *ret, int thr_i, uint32_t start,
                                 uint32_t task_n, block chi_seed) {
    if (task_n == 0)
      return;
    block *left = andgate_left_buffer;
    block *right = andgate_right_buffer;
    block *gateout = andgate_out_buffer;

    if (party == ALICE) {
      for (uint32_t i = start; i < start + task_n; ++i) {
        block A0, A1;
        gfmul(left[i], right[i], &A0);
        A1 = (getLSB(left[i]) ? right[i] : zero_block) ^
             (getLSB(right[i]) ? left[i] : zero_block) ^
             gateout[i];
        left[i] = A0;
        right[i] = A1;
      }
    } else {
      for (uint32_t i = start; i < start + task_n; ++i) {
        block B;
        gfmul(left[i], right[i], &B);
        block tmp;
        gfmul(gateout[i], this->delta, &tmp);
        B = B ^ tmp;
        left[i] = B;
      }
    }

    block *chi = new block[task_n];
    uni_hash_coeff_gen(chi, chi_seed, task_n);
    if (party == ALICE) {
      vector_inn_prdt_sum_red(ret + 2 * thr_i, chi, left + start, task_n);
      vector_inn_prdt_sum_red(ret + 2 * thr_i + 1, chi, right + start, task_n);
    } else
      vector_inn_prdt_sum_red(ret + thr_i, chi, left + start, task_n);

    delete[] chi;
  }

  /*
   * verify the output: open one bit per element, drain its MAC into
   * the auth_hash transcript, and let finalize_macs() compare digests
   * at teardown.
   */
  void verify_output(bool *b, const block *output, int length) {
    for (int i = 0; i < length; ++i) {
      if (party == ALICE) {
        b[i] = getLSB(output[i]);
        io->send_bit(b[i]);
      } else {
        b[i] = io->recv_bit();
      }
    }
    if (party == ALICE) {
      auth_hash.put_block(output, length);
    } else {
      if (auth_tmp.size() < (size_t)length)
        auth_tmp.resize(length);
      for (int i = 0; i < length; ++i)
        auth_tmp[i] = xor_delta_if(output[i], b[i]);
      auth_hash.put_block(auth_tmp.data(), length);
    }
  }

  bool finalize_macs() {
    char digest[Hash::DIGEST_SIZE];
    auth_hash.digest(digest);
    if (party == ALICE) {
      io->send_data(digest, Hash::DIGEST_SIZE);
      io->flush();
      return true;
    } else {
      char digest2[Hash::DIGEST_SIZE];
      io->recv_data(digest2, Hash::DIGEST_SIZE);
      return memcmp(digest, digest2, Hash::DIGEST_SIZE) == 0;
    }
  }

  void sync() {
    io->flush();
    for (int i = 0; i < threads; ++i)
      ios[i]->flush();
  }
};

} // namespace emp
#endif
