#ifndef EMP_ZK_BOOL_PROVER_H__
#define EMP_ZK_BOOL_PROVER_H__

// Prover-side Backend (ALICE). Owns the ALICE branches of the
// authenticated-triple protocol that used to live in OSTriple.
// Included from zk_bool.h.

namespace emp {
using namespace std;

class ZKBoolProver : public ZKBoolBase {
public:
  ZKBoolProver(BoolIO *io) : ZKBoolBase(ALICE, io) {
    // PUBLIC label for bit 1 has its LSB set so getLSB() reads back the
    // cleartext value. (Verifier instead xors zdelta into pub_label[1].)
    pub_label[1] = pub_label[1] ^ makeBlock(0, 1);
  }

  ~ZKBoolProver() override {
    // Flush any leftover f2k batch first. f2k_check_manage is virtual and
    // draws from the still-open Ferret session, so it must run in the
    // subclass dtor (the base dtor only frees the f2k objects).
    if (f2k_ready && f2k_check_cnt != 0)
      f2k_check_manage();

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
      authenticated_bits_input(label, in, static_cast<int64_t>(n));
    else if (from_party == PUBLIC)
      for (size_t i = 0; i < n; ++i) label[i] = pub_label[in[i]];
  }

  void reveal(bool *out, int to_party, const void *in, size_t n) override {
    const block *label = static_cast<const block *>(in);
    int64_t len = static_cast<int64_t>(n);
    if (to_party == ALICE) {
      // Local read-out — no MAC check needed since prover is the trust root.
      for (int64_t i = 0; i < len; ++i) out[i] = getLSB(label[i]);
    } else { // BOB or PUBLIC
      verify_output(out, label, len);
    }
  }

private:
  // Authenticated-bit input: receive a fresh COT pair, embed the cleartext
  // bit in the LSB, send the masking flip to BOB.
  void authenticated_bits_input(block *auth, const bool *in, int64_t len) {
    ferret->next_n(auth, len);
    for (int64_t i = 0; i < len; ++i) {
      bool buff = getLSB(auth[i]) ^ in[i];
      auth[i] = with_lsb(auth[i], in[i]);
      io->send_bit(buff);
    }
  }

  // Authenticated AND: compute s = a·b on cleartext, mask the pre-drawn COT
  // to hold s, send the masking bit. The fresh COT is read out of
  // andgate_out_buffer (pre-filled in the ctor); the same slot is
  // overwritten with the output MAC, buffering it alongside the inputs for
  // the eventual batch correctness check. When the buffer fills, run the
  // check then refill — so the COT recv is one burst per CHECK_SZ gates.
  block auth_compute_and(block a, block b) {
    if (check_cnt == CHECK_SZ) {
      andgate_correctness_check_manage();
      check_cnt = 0;
      ferret->next_n(andgate_out_buffer.data(), CHECK_SZ);
    }

    block auth = andgate_out_buffer[check_cnt];   // pre-drawn fresh COT
    andgate_left_buffer[check_cnt]  = a;
    andgate_right_buffer[check_cnt] = b;

    bool s = getLSB(a) and getLSB(b);
    bool d = s ^ getLSB(auth);
    auth = with_lsb(auth, s);
    io->send_bit(d);

    andgate_out_buffer[check_cnt] = auth;          // overwrite with output MAC
    check_cnt++;
    return auth;
  }

  // Output reveal: send each cleartext bit, then drop the MACs into the
  // auth_hash transcript. The destructor sends the digest; the verifier's
  // matching digest fails error() if the prover lied.
  void verify_output(bool *b, const block *output, int64_t length) {
    for (int64_t i = 0; i < length; ++i) {
      b[i] = getLSB(output[i]);
      io->send_bit(b[i]);
    }
    auth_hash.put_block(output, length);
  }

  void andgate_correctness_check(block *ret, int64_t task_n,
                                 block chi_seed) override {
    if (task_n == 0) return;
    const block *left    = andgate_left_buffer.data();
    const block *right   = andgate_right_buffer.data();
    const block *gateout = andgate_out_buffer.data();

    // Fold the buffered triples into (ret[0], ret[1]) one cache-resident
    // chunk at a time: per chunk derive its chi slice and form the per-gate
    // coefficients (A0 = left*right; A1 the linear term, branchless via
    // select_mask[lsb]). Avoids rewriting the multi-MB triple buffers and a
    // task_n-sized chi array. Accumulate the *unreduced* 256-bit chi inner
    // products across all chunks and reduce once at the end -- GF(2^128)
    // reduction is linear over XOR, so this is bit-identical to one big
    // reduced pass while paying one reduce per output instead of per chunk.
    PRG prg(&chi_seed);
    constexpr int64_t kChunk = 1024;
    block chi[kChunk], A0[kChunk], A1[kChunk];
    block acc0[2] = {zero_block, zero_block}, acc1[2] = {zero_block, zero_block};
    for (int64_t base = 0; base < task_n; base += kChunk) {
      const int64_t m = (task_n - base < kChunk) ? (task_n - base) : kChunk;
      prg.random_block(chi, m);
      for (int64_t i = 0; i < m; ++i) {
        const block l = left[base + i], rt = right[base + i];
        gfmul(l, rt, &A0[i]);
        A1[i] = (select_mask[getLSB(l)]  & rt) ^
                (select_mask[getLSB(rt)] & l)  ^ gateout[base + i];
      }
      block p[2];
      vector_inn_prdt_sum_no_red(p, chi, A0, m);
      acc0[0] = acc0[0] ^ p[0];  acc0[1] = acc0[1] ^ p[1];
      vector_inn_prdt_sum_no_red(p, chi, A1, m);
      acc1[0] = acc1[0] ^ p[0];  acc1[1] = acc1[1] ^ p[1];
    }
    ret[0] = reduce(acc0[0], acc0[1]);
    ret[1] = reduce(acc1[0], acc1[1]);
  }

  void andgate_correctness_aggregate(block *sum) override {
    block ope_data[128];
    ferret->next_n(ope_data, 128);
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
    A_star[0] = A_star[0] ^ sum[0];
    A_star[1] = A_star[1] ^ sum[1];
    io->send_data(A_star, 2 * sizeof(block));
  }

  // ---- f2k wire ops (ALICE) -------------------------------------------

  void f2k_add_const(F2kAuthValue &out, const F2kAuthValue &in,
                     block c) override {
    out.val = in.val ^ c;   // add c on the cleartext side; mac unchanged
    out.mac = in.mac;
  }

  void f2k_mul(F2kAuthValue &out, const F2kAuthValue &a,
               const F2kAuthValue &b) override {
    f2k_init();
    if (f2k_check_cnt == f2k_buffer_sz) {
      f2k_check_manage();
      f2k_check_cnt = 0;
    }
    if (f2k_authval_cnt == f2k_buffer_sz)
      f2k_pre_buffer_refill();
    f2k_left_val[f2k_check_cnt] = a.val;
    f2k_left_mac[f2k_check_cnt] = a.mac;
    f2k_rght_val[f2k_check_cnt] = b.val;
    f2k_rght_mac[f2k_check_cnt] = b.mac;

    // s = a·b on cleartext; mask the pre-drawn VOLE value to hold it, ship
    // the masking difference d. mac is the VOLE mac for this gate output.
    block valc, d;
    gfmul(a.val, b.val, &valc);
    d = valc ^ f2k_auth_buffer[f2k_authval_cnt].val;
    f2k_auth_buffer[f2k_authval_cnt].val = valc;
    io->send_data(&d, sizeof(block));
    out.val = valc;
    out.mac = f2k_auth_buffer[f2k_authval_cnt].mac;
    f2k_check_cnt++;
    f2k_authval_cnt++;
  }

  // Cleartext product of the N input values (the Δ^N coefficient that the
  // degree-N product proof leaves to the caller).
  block f2k_mul_v(int64_t N, const block *vals) override {
    block v = vals[0];
    for (int64_t i = 1; i < N; ++i) gfmul(vals[i], v, &v);
    return v;
  }

  void f2k_check_manage() override {
    io->flush();
    block seed = io->get_hash_block();
    block sum[2] = { zero_block, zero_block };
    f2k_check(sum, f2k_check_cnt, seed);

    block ope_data[128];
    ferret->next_n(ope_data, 128);
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
    A_star[0] = A_star[0] ^ sum[0];
    A_star[1] = A_star[1] ^ sum[1];
    io->send_data(A_star, 2 * sizeof(block));
    io->flush();
  }

 private:
  // Fold the buffered f2k multiplication triples into (Δ⁰, Δ¹) check
  // coefficients (A0 = ma·mb, A1 the linear term + the output mac), then
  // chi-reduce. left/right val buffers are reused as scratch.
  void f2k_check(block *ret, int64_t task_n, block chi_seed) {
    if (task_n == 0) return;
    block *lval = f2k_left_val.data();
    block *lmac = f2k_left_mac.data();
    block *rval = f2k_rght_val.data();
    block *rmac = f2k_rght_mac.data();
    const int64_t omac_base = f2k_authval_cnt - f2k_check_cnt;
    for (int64_t i = 0; i < task_n; ++i) {
      block A0, A1, tmp;
      gfmul(lmac[i], rmac[i], &A0);
      gfmul(lval[i], rmac[i], &tmp);
      gfmul(rval[i], lmac[i], &A1);
      A1 = A1 ^ tmp;
      A1 = A1 ^ f2k_auth_buffer[omac_base + i].mac;
      lval[i] = A0;
      rval[i] = A1;
    }
    std::vector<block> chi(task_n);
    PRG(&chi_seed).random_block(chi.data(), task_n);
    vector_inn_prdt_sum_red(ret + 0, chi.data(), lval, task_n);
    vector_inn_prdt_sum_red(ret + 1, chi.data(), rval, task_n);
  }

 public:
};

inline ZKBoolProver *get_bool_backend_prv() {
  return static_cast<ZKBoolProver *>(backend);
}

} // namespace emp
#endif
