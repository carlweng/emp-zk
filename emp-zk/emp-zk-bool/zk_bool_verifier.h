#ifndef EMP_ZK_BOOL_VERIFIER_H__
#define EMP_ZK_BOOL_VERIFIER_H__

// Verifier-side Backend (BOB). Owns the BOB branches of the
// authenticated-triple protocol that used to live in OSTriple.
// Included from zk_bool.h.

namespace emp {
using namespace std;

class ZKBoolVerifier : public ZKBoolBase {
public:
  // The verifier holds delta (and zdelta = delta ^ 1 for negation). Both
  // are also reachable via ZKBoolBase::delta; zdelta is verifier-
  // specific because NOT folds it on the wire.
  block zdelta;

  ZKBoolVerifier(BoolIO *io) : ZKBoolBase(BOB, io) {
    zdelta = delta ^ makeBlock(0, 1);
    // PUBLIC label for bit 1: xor zdelta in so the wire MAC is right
    // even though there's no cleartext flip.
    pub_label[1] = pub_label[1] ^ zdelta;
  }

  ~ZKBoolVerifier() override {
    if (check_cnt != 0)
      andgate_correctness_check_manage();

    // finalize_macs (VER side): hash the wire MACs we computed for revealed
    // outputs, compare against the prover's digest. Mismatch → cheat.
    char digest[Hash::DIGEST_SIZE];
    auth_hash.digest(digest);
    char digest2[Hash::DIGEST_SIZE];
    io->recv_data(digest2, Hash::DIGEST_SIZE);
    if (memcmp(digest, digest2, Hash::DIGEST_SIZE) != 0)
      error("emp-zk-bool finalize");
  }

  // ---- Backend virtuals --------------------------------------------------

  void not_gate(void *o, const void *in) override {
    // NOT folds zdelta so the MAC stays consistent under negation.
    *static_cast<block *>(o) = *static_cast<const block *>(in) ^ zdelta;
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
    if (to_party == BOB || to_party == PUBLIC)
      verify_output(out, static_cast<const block *>(in),
                    static_cast<int64_t>(n));
  }

private:
  // ---- BOB-side OSTriple methods ----------------------------------------

  // Authenticated-bit input: receive the prover's masking flips, fold them
  // into the COT keys to recover the per-bit MAC structure.
  void authenticated_bits_input(block *auth, const bool *in, int64_t len) {
    ferret->next_n(auth, len);
    for (int64_t i = 0; i < len; ++i) {
      bool buff = io->recv_bit();
      auth[i] = clear_lsb(xor_delta_if(auth[i], buff));
    }
  }

  // Authenticated AND: receive the prover's masking bit, reconstruct the
  // wire key. Buffer the inputs+output for the eventual batch check.
  block auth_compute_and(block a, block b) {
    block auth;
    if (check_cnt == CHECK_SZ) {
      andgate_correctness_check_manage();
      check_cnt = 0;
    }

    ferret->next_n(&auth, 1);
    andgate_left_buffer[check_cnt]  = a;
    andgate_right_buffer[check_cnt] = b;

    bool d = io->recv_bit();
    auth = clear_lsb(xor_delta_if(auth, d));

    andgate_out_buffer[check_cnt] = auth;
    check_cnt++;
    return auth;
  }

  // Output reveal: receive each claimed cleartext bit, recompute the
  // expected MAC under our own delta, drop into the auth_hash transcript.
  // The destructor compares this digest against the prover's.
  void verify_output(bool *b, const block *output, int64_t length) {
    for (int64_t i = 0; i < length; ++i)
      b[i] = io->recv_bit();
    if ((int64_t)auth_tmp.size() < length)
      auth_tmp.resize(length);
    for (int64_t i = 0; i < length; ++i)
      auth_tmp[i] = xor_delta_if(output[i], b[i]);
    auth_hash.put_block(auth_tmp.data(), length);
  }

  // ---- Per-thread + aggregation hooks (called from base skeleton) -------

  void andgate_correctness_check(block *ret, int64_t task_n,
                                 block chi_seed) override {
    if (task_n == 0) return;
    block *left    = andgate_left_buffer.data();
    block *right   = andgate_right_buffer.data();
    block *gateout = andgate_out_buffer.data();

    for (int64_t i = 0; i < task_n; ++i) {
      block B;
      gfmul(left[i], right[i], &B);
      block tmp;
      gfmul(gateout[i], delta, &tmp);
      B = B ^ tmp;
      left[i] = B;
    }

    std::vector<block> chi(task_n);
    uni_hash_coeff_gen(chi.data(), chi_seed, task_n);
    vector_inn_prdt_sum_red(ret + 0, chi.data(), left, task_n);
  }

  void andgate_correctness_aggregate(block *sum) override {
    block ope_data[128];
    ferret->next_n(ope_data, 128);
    block B_star;
    pack.packing(&B_star, ope_data);
    B_star = B_star ^ sum[0];
    block A_star[2];
    io->recv_data(A_star, 2 * sizeof(block));
    block W;
    gfmul(A_star[1], delta, &W);
    W = W ^ A_star[0];
    if (cmpBlock(&W, &B_star, 1) != 1)
      error("emp_zk_bool AND batch check");
  }
};

inline ZKBoolVerifier *get_bool_backend_ver() {
  return static_cast<ZKBoolVerifier *>(backend);
}

} // namespace emp
#endif
