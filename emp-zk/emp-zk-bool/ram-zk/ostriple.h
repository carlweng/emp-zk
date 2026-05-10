#ifndef EMP_ZK_RAM_OSTRIPLE_H__
#define EMP_ZK_RAM_OSTRIPLE_H__

#include "emp-zk/emp-vole-f2k/svole.h"
#include "emp-zk/emp-zk-bool/ram-zk/poly_prdt.h"

// =====================================================================
// Authenticated triple stream backing emp-zk-ram. Mirrors the
// ZKBoolBase / ZKBoolProver / ZKBoolVerifier split in emp-zk-bool:
// shared state + pre-f2k buffer + sVOLE / RamPolyPrdt go on the base;
// each role owns its own arithmetic / batch-check methods (no runtime
// `if (party == ALICE) … else …` dispatch at the call site).
// =====================================================================

template <typename IO> class RamOSTripleBase {
public:
  int party;
  block delta;

  int authf2k_cnt = 0, check_cnt = 0;
  std::vector<block> auth_buffer_val;
  std::vector<block> auth_buffer_mac;
  std::vector<block> andgate_buffer_left_val;
  std::vector<block> andgate_buffer_left_mac;
  std::vector<block> andgate_buffer_rght_val;
  std::vector<block> andgate_buffer_rght_mac;

  GaloisFieldPacking pack;

  IO *io;
  PRG prg;
  FerretCOT *ferret = nullptr;
  SVoleF2k<IO> *svole = nullptr;
  RamPolyPrdt<IO> *polyprdt = nullptr;
  // One chunk of scratch for ferret->rcot_*_next; allocated lazily in
  // andgate_correctness_check_manage. The bool backend opens the
  // long-lived ferret session, so rcot_*_next is callable here.
  std::vector<block> ope_buf;

  int64_t BUFFER_MEM_SZ = -1, BUFFER_SZ = -1;

  RamOSTripleBase(int party, IO *io, FerretCOT *ferret)
      : party(party), io(io), ferret(ferret) {
    if (party == BOB)
      this->delta = ferret->Delta;
    else
      this->delta = zero_block;
    // SVoleF2k still takes IO** + threads + (implicit) pool. Pass a
    // single-element array + threads=1; with threads=1 the SVoleF2k
    // internal threading skeleton degenerates to a serial loop.
    IO *ios_one[1] = { io };
    svole = new SVoleF2k<IO>(party, /*threads=*/1, ios_one, ferret);
    svole->setup(delta);
    BUFFER_MEM_SZ = svole->param.n;
    BUFFER_SZ = svole->param.buf_sz();

    auth_buffer_val.resize(BUFFER_MEM_SZ);
    auth_buffer_mac.resize(BUFFER_MEM_SZ);
    andgate_buffer_left_val.resize(BUFFER_SZ);
    andgate_buffer_left_mac.resize(BUFFER_SZ);
    andgate_buffer_rght_val.resize(BUFFER_SZ);
    andgate_buffer_rght_mac.resize(BUFFER_SZ);

    polyprdt = new RamPolyPrdt<IO>(party, io, ferret);

    pre_f2k_buffer_refill();
  }

  // Note: the subclass dtor must flush any pending andgate batch via
  // andgate_correctness_check_manage() *before* base destruction —
  // calling that virtual after the subclass vtable is gone aborts
  // with "Pure virtual function called!".
  virtual ~RamOSTripleBase() {
    delete polyprdt;
    delete svole;
  }

  uint64_t communication() { return io->counter; }
  void sync() { io->flush(); }

  void pre_f2k_buffer_refill() {
    svole->extend_inplace(auth_buffer_val.data(),
                          auth_buffer_mac.data(), BUFFER_MEM_SZ);
    authf2k_cnt = 0;
  }

  bool andgate_buf_not_empty() { return check_cnt != 0; }

  // ---- Role-specific arithmetic (pure virtual) -------------------------

  virtual void compute_add_const(block &valb, block &macb, const block &vala,
                                 const block &maca, const block &c) = 0;
  virtual void compute_mul(block &valc, block &macc, block vala, block maca,
                           block valb, block macb) = 0;

  // Polynomial-value hook: ALICE returns ⊗_i vals[i] (gfmul chain over
  // the N input cleartext blocks); BOB returns zero_block (it has no
  // cleartext). Drives the templated compute_mul_poly<N> below.
  virtual block compute_mul_v(int N, const block *vals) = 0;

  // ---- compute_mul_poly<N> ---------------------------------------------
  //
  // One templated entry point covering the former compute_mul{3,4,5}.
  // N is the number of (val, mac) input pairs; the variadic `args`
  // takes them interleaved in the same shape the call sites used:
  //   compute_mul_poly(out_val, out_mac, v1, m1, v2, m2, …, vN, mN)
  // N is deduced from the variadic count (sizeof...(args) / 2).

  template <typename... Args>
  void compute_mul_poly(block &val, block &mac, Args... args) {
    static_assert(sizeof...(args) % 2 == 0,
                  "compute_mul_poly expects (val, mac) pairs");
    constexpr int N = sizeof...(args) / 2;
    static_assert(N >= 3 && N <= 5,
                  "compute_mul_poly supports N=3, 4, 5 (matches polyPrdt3/4/5)");

    // Pack the variadic into a flat 2N-block array, then split into
    // (vals, macs); polyPrdtN takes the val and mac sides separately
    // and the v-hook only needs vals.
    block flat[2 * N] = { static_cast<block>(args)... };
    block vals[N], macs[N];
    for (int i = 0; i < N; ++i) {
      vals[i] = flat[2 * i];
      macs[i] = flat[2 * i + 1];
    }

    block v = compute_mul_v(N, vals);
    block m = pack_v(v);
    polyprdt->template polyPrdtN<N>(vals, macs, m);

    val = v;
    mac = m;
  }

  // ---- Batch correctness check (role-specific) -------------------------

  virtual void andgate_correctness_check_manage() = 0;

private:
  // GaloisFieldPacking::base[i] = X^i is no longer exposed on emp-tool
  // main; pack.packing(res, data) over 128 wires computes the same
  // Σ data[i]·X^i directly. Wraps the lowInt/highInt prep + packing
  // path used by all three compute_mul{3,4,5} variants.
  block pack_v(block v) {
    uint64_t low  = LOW64(v);
    uint64_t high = HIGH64(v);
    Integer lowInt(65, low, ALICE);
    Integer highInt(65, high, ALICE);
    block packbuf[128], m;
    memcpy(packbuf,      lowInt.bits.data(),  64 * sizeof(block));
    memcpy(packbuf + 64, highInt.bits.data(), 64 * sizeof(block));
    pack.packing(&m, packbuf);
    return m;
  }
};

// =====================================================================
// Prover (ALICE) side
// =====================================================================

template <typename IO> class RamOSTripleProver : public RamOSTripleBase<IO> {
public:
  using Base = RamOSTripleBase<IO>;
  using Base::party;
  using Base::delta;
  using Base::io;
  using Base::ferret;
  using Base::pack;
  using Base::polyprdt;
  using Base::ope_buf;
  using Base::auth_buffer_val;
  using Base::auth_buffer_mac;
  using Base::andgate_buffer_left_val;
  using Base::andgate_buffer_left_mac;
  using Base::andgate_buffer_rght_val;
  using Base::andgate_buffer_rght_mac;
  using Base::authf2k_cnt;
  using Base::check_cnt;
  using Base::BUFFER_SZ;
  using Base::pre_f2k_buffer_refill;

  RamOSTripleProver(IO *io, FerretCOT *ferret) : Base(ALICE, io, ferret) {}

  ~RamOSTripleProver() override {
    if (check_cnt != 0) andgate_correctness_check_manage();
  }

  void compute_add_const(block &valb, block &macb, const block &vala,
                         const block &maca, const block &c) override {
    // ALICE adds c on the cleartext side; mac is unchanged.
    valb = vala ^ c;
    macb = maca;
  }

  void compute_mul(block &valc, block &macc, block vala, block maca,
                   block valb, block macb) override {
    if (check_cnt == BUFFER_SZ) {
      andgate_correctness_check_manage();
      check_cnt = 0;
    }
    if (authf2k_cnt == BUFFER_SZ) {
      pre_f2k_buffer_refill();
      authf2k_cnt = 0;
    }
    andgate_buffer_left_val[check_cnt] = vala;
    andgate_buffer_left_mac[check_cnt] = maca;
    andgate_buffer_rght_val[check_cnt] = valb;
    andgate_buffer_rght_mac[check_cnt] = macb;

    block d;
    gfmul(vala, valb, &valc);
    d = valc ^ auth_buffer_val[authf2k_cnt];
    auth_buffer_val[authf2k_cnt] = valc;
    io->send_data(&d, sizeof(block));
    macc = auth_buffer_mac[authf2k_cnt];
    check_cnt++;
    authf2k_cnt++;
  }

  // Prover: chain-multiply N values: v = vals[0] * vals[1] * … * vals[N-1].
  block compute_mul_v(int N, const block *vals) override {
    block v = vals[0];
    for (int i = 1; i < N; ++i) gfmul(vals[i], v, &v);
    return v;
  }

  void andgate_correctness_check_manage() override {
    io->flush();
    block seed = io->get_hash_block();
    block sum[2] = { zero_block, zero_block };
    andgate_correctness_check_alice(sum, check_cnt, seed);

    if (ope_buf.empty()) ope_buf.resize(ferret->chunk_ots());
    // Prover side: ferret is BOB → OT-receiver → use rcot_recv_next.
    ferret->rcot_recv_next(ope_buf.data());
    block *ope_data = ope_buf.data();
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
  void andgate_correctness_check_alice(block *ret, uint32_t task_n,
                                       block chi_seed) {
    if (task_n == 0) return;
    block *lval = andgate_buffer_left_val.data();
    block *lmac = andgate_buffer_left_mac.data();
    block *rval = andgate_buffer_rght_val.data();
    block *rmac = andgate_buffer_rght_mac.data();
    block *omac = auth_buffer_mac.data() + authf2k_cnt - check_cnt;

    for (uint32_t i = 0; i < task_n; ++i) {
      block A0, A1, tmp;
      gfmul(lmac[i], rmac[i], &A0);
      gfmul(lval[i], rmac[i], &tmp);
      gfmul(rval[i], lmac[i], &A1);
      A1 = A1 ^ tmp;
      A1 = A1 ^ omac[i];
      lval[i] = A0;
      rval[i] = A1;
    }

    std::vector<block> chi(task_n);
    uni_hash_coeff_gen(chi.data(), chi_seed, task_n);
    vector_inn_prdt_sum_red(ret + 0, chi.data(), lval, task_n);
    vector_inn_prdt_sum_red(ret + 1, chi.data(), rval, task_n);
  }
};

// =====================================================================
// Verifier (BOB) side
// =====================================================================

template <typename IO> class RamOSTripleVerifier : public RamOSTripleBase<IO> {
public:
  using Base = RamOSTripleBase<IO>;
  using Base::party;
  using Base::delta;
  using Base::io;
  using Base::ferret;
  using Base::pack;
  using Base::polyprdt;
  using Base::ope_buf;
  using Base::auth_buffer_val;
  using Base::auth_buffer_mac;
  using Base::andgate_buffer_left_val;
  using Base::andgate_buffer_left_mac;
  using Base::andgate_buffer_rght_val;
  using Base::andgate_buffer_rght_mac;
  using Base::authf2k_cnt;
  using Base::check_cnt;
  using Base::BUFFER_SZ;
  using Base::pre_f2k_buffer_refill;

  RamOSTripleVerifier(IO *io, FerretCOT *ferret) : Base(BOB, io, ferret) {}

  ~RamOSTripleVerifier() override {
    if (check_cnt != 0) andgate_correctness_check_manage();
  }

  void compute_add_const(block &valb, block &macb, const block &,
                         const block &maca, const block &c) override {
    block d;
    gfmul(delta, c, &d);
    macb = maca ^ d;
    valb = zero_block;     // verifier has no cleartext
  }

  void compute_mul(block &valc, block &macc, block vala, block maca,
                   block valb, block macb) override {
    if (check_cnt == BUFFER_SZ) {
      andgate_correctness_check_manage();
      check_cnt = 0;
    }
    if (authf2k_cnt == BUFFER_SZ) {
      pre_f2k_buffer_refill();
      authf2k_cnt = 0;
    }
    // Verifier doesn't touch the val buffers in andgate_correctness_check_bob,
    // but populate them anyway to keep the buffer shape symmetric with the
    // prover side.
    andgate_buffer_left_val[check_cnt] = vala;
    andgate_buffer_left_mac[check_cnt] = maca;
    andgate_buffer_rght_val[check_cnt] = valb;
    andgate_buffer_rght_mac[check_cnt] = macb;

    block d;
    io->recv_data(&d, sizeof(block));
    gfmul(d, delta, &d);
    auth_buffer_mac[authf2k_cnt] ^= d;
    valc = zero_block;
    macc = auth_buffer_mac[authf2k_cnt];
    check_cnt++;
    authf2k_cnt++;
  }

  // Verifier: no cleartext, so v is always zero.
  block compute_mul_v(int, const block *) override { return zero_block; }

  void andgate_correctness_check_manage() override {
    io->flush();
    block seed = io->get_hash_block();
    block sum[2] = { zero_block, zero_block };
    andgate_correctness_check_bob(sum, check_cnt, seed);

    if (ope_buf.empty()) ope_buf.resize(ferret->chunk_ots());
    // Verifier side: ferret is ALICE → OT-sender → use rcot_send_next.
    ferret->rcot_send_next(ope_buf.data());
    block *ope_data = ope_buf.data();
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
    io->flush();
  }

private:
  void andgate_correctness_check_bob(block *ret, uint32_t task_n,
                                     block chi_seed) {
    if (task_n == 0) return;
    block *lmac = andgate_buffer_left_mac.data();
    block *rmac = andgate_buffer_rght_mac.data();
    block *omac = auth_buffer_mac.data() + authf2k_cnt - check_cnt;
    block *lval = andgate_buffer_left_val.data();   // reused as scratch

    for (uint32_t i = 0; i < task_n; ++i) {
      block B, tmp;
      gfmul(lmac[i], rmac[i], &B);
      gfmul(omac[i], delta, &tmp);
      B = B ^ tmp;
      lval[i] = B;
    }

    std::vector<block> chi(task_n);
    uni_hash_coeff_gen(chi.data(), chi_seed, task_n);
    vector_inn_prdt_sum_red(ret + 0, chi.data(), lval, task_n);
  }
};

#endif
