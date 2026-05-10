#ifndef EMP_ZK_BOOL_BACKEND_PRV_H__
#define EMP_ZK_BOOL_BACKEND_PRV_H__

// Prover-side Backend (ALICE). Owns the ALICE branches of the
// authenticated-triple protocol that used to live in OSTriple.
// Included from zk_bool_backend.h.

namespace emp {

class ZKBoolBackendPrv : public ZKBoolBackendBase {
public:
  ZKBoolBackendPrv(BoolIO **ios, int threads)
      : ZKBoolBackendBase(ALICE, ios, threads) {
    // PUBLIC label for bit 1 has its LSB set so getLSB() reads back the
    // cleartext value. (Verifier instead xors zdelta into pub_label[1].)
    pub_label[1] = pub_label[1] ^ makeBlock(0, 1);
  }

  ~ZKBoolBackendPrv() override {
    if (check_cnt != 0)
      andgate_correctness_check_manage();

    // finalize_macs (PRV side): hash the revealed wire MACs into a digest
    // and ship it. Verifier compares against its own.
    char digest[Hash::DIGEST_SIZE];
    auth_hash.digest(digest);
    io->send_data(digest, Hash::DIGEST_SIZE);
    io->flush();
  }

  // ---- Backend virtuals --------------------------------------------------

  void not_gate(void *o, const void *in) override {
    // Canonical XOR-with-1: flips the cleartext LSB; the MAC is unchanged.
    *static_cast<block *>(o) =
        *static_cast<const block *>(in) ^ makeBlock(0, 1);
  }

  void and_gate(void *o, const void *l, const void *r) override {
    ++gid;
    *static_cast<block *>(o) = auth_compute_and(
        *static_cast<const block *>(l), *static_cast<const block *>(r));
  }

  void feed(void *out, int from_party, const bool *in, size_t n) override {
    block *label = static_cast<block *>(out);
    if (from_party == ALICE)
      authenticated_bits_input(label, in, static_cast<int>(n));
    else if (from_party == PUBLIC)
      for (size_t i = 0; i < n; ++i) label[i] = pub_label[in[i]];
  }

  void reveal(bool *out, int to_party, const void *in, size_t n) override {
    const block *label = static_cast<const block *>(in);
    int len = static_cast<int>(n);
    if (to_party == ALICE) {
      // Local read-out — no MAC check needed since prover is the trust root.
      for (int i = 0; i < len; ++i) out[i] = getLSB(label[i]);
    } else { // BOB or PUBLIC
      verify_output(out, label, len);
    }
  }

private:
  // ---- ALICE-side OSTriple methods --------------------------------------

  // Authenticated-bit input: receive a fresh COT pair, embed the cleartext
  // bit in the LSB, send the masking flip to BOB.
  void authenticated_bits_input(block *auth, const bool *in, int len) {
    take_rcot(auth, len);
    for (int i = 0; i < len; ++i) {
      bool buff = getLSB(auth[i]) ^ in[i];
      auth[i] = with_lsb(auth[i], in[i]);
      io->send_bit(buff);
    }
  }

  // Authenticated AND: compute s = a·b on cleartext, mask one COT pair to
  // hold s, send the masking bit. Buffer the inputs+output for the eventual
  // batch correctness check; trigger the check when the buffer fills.
  block auth_compute_and(block a, block b) {
    block auth;
    if (check_cnt == CHECK_SZ) {
      andgate_correctness_check_manage();
      check_cnt = 0;
    }

    take_rcot(&auth, 1);
    andgate_left_buffer[check_cnt]  = a;
    andgate_right_buffer[check_cnt] = b;

    bool s = getLSB(a) and getLSB(b);
    bool d = s ^ getLSB(auth);
    auth = with_lsb(auth, s);
    io->send_bit(d);

    andgate_out_buffer[check_cnt] = auth;
    check_cnt++;
    return auth;
  }

  // Output reveal: send each cleartext bit, then drop the MACs into the
  // auth_hash transcript. The destructor sends the digest; the verifier's
  // matching digest fails error() if the prover lied.
  void verify_output(bool *b, const block *output, int length) {
    for (int i = 0; i < length; ++i) {
      b[i] = getLSB(output[i]);
      io->send_bit(b[i]);
    }
    auth_hash.put_block(output, length);
  }

  // ---- Per-thread + aggregation hooks (called from base skeleton) -------

  void andgate_correctness_check(block *ret, int thr_i, uint32_t start,
                                  uint32_t task_n, block chi_seed) override {
    if (task_n == 0) return;
    block *left    = andgate_left_buffer.data();
    block *right   = andgate_right_buffer.data();
    block *gateout = andgate_out_buffer.data();

    for (uint32_t i = start; i < start + task_n; ++i) {
      block A0, A1;
      gfmul(left[i], right[i], &A0);
      A1 = (getLSB(left[i])  ? right[i] : zero_block) ^
           (getLSB(right[i]) ? left[i]  : zero_block) ^
           gateout[i];
      left[i]  = A0;
      right[i] = A1;
    }

    std::vector<block> chi(task_n);
    uni_hash_coeff_gen(chi.data(), chi_seed, task_n);
    vector_inn_prdt_sum_red(ret + 2 * thr_i,     chi.data(), left  + start, task_n);
    vector_inn_prdt_sum_red(ret + 2 * thr_i + 1, chi.data(), right + start, task_n);
  }

  void andgate_correctness_aggregate(block *sum) override {
    block ope_data[128];
    take_rcot(ope_data, 128);
    uint64_t ch_bits[2];
    for (int i = 0; i < 2; ++i) {
      ch_bits[i] = getLSB(ope_data[64 * i + 63]) ? 1 : 0;
      for (int j = 62; j >= 0; --j) {
        ch_bits[i] <<= 1;
        if (getLSB(ope_data[64 * i + j])) ch_bits[i]++;
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
  }
};

inline ZKBoolBackendPrv *get_bool_backend_prv() {
  return static_cast<ZKBoolBackendPrv *>(backend);
}

} // namespace emp
#endif
