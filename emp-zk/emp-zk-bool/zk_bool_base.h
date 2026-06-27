#ifndef EMP_ZK_BOOL_BASE_H__
#define EMP_ZK_BOOL_BASE_H__

// The emp-zk-bool proof engine — a standalone class (no emp-tool Backend
// inheritance, no global pointer) wrapped by ZKBoolContext (zk_context.h) and
// owned by ZKBoolSession (zk_session.h). Single-threaded; one BoolIO* drives both
// the gate-level bool stream and Ferret's OT-extension data.
//
// Layout:
//   - zk_bool_base.h     — ZKBoolBase: shared state, the typed gate / I-O surface
//                          (public_block/xor_block + the virtual and_block /
//                          not_block / feed_bits / reveal_bits), and the AND-gate
//                          batch correctness-check entry point with virtual hooks
//                          for the role-specific check and aggregator.
//   - zk_bool_prover.h   — ZKBoolProver: ALICE-side methods (auth_compute_and,
//                          authenticated_bits_input, verify_output, finalize_macs,
//                          hooks) and the gate/I-O overrides routing to them.
//   - zk_bool_verifier.h — symmetric for the verifier.
//
// The triple-generation state and methods live directly on the engine
// hierarchy: shared state on the base, prover-specific methods in ZKBoolProver,
// verifier-specific in ZKBoolVerifier — the party split is by subclass, so no
// method carries runtime party dispatch (`if (party == ALICE) … else …`).

#include <emp-tool/emp-tool.h>
#include "emp-ot/emp-ot.h"

#include "emp-zk/emp-zk-bool/zk_wire.h"
#include "emp-zk/emp-zk-bool/bool_io.h"
#include "emp-zk/emp-zk-bool/polynomial.h"
#include <future>
#include <memory>
#include <vector>

namespace emp {
using namespace std;

// The f2k wire type: an authenticated F(2^128) value (val, mac). Same
// storage as the sVOLE carrier; named for its role as a circuit wire.
using F2kAuthValue = AuthValueF2k;

// The emp-zk-bool proof engine: a standalone class (no emp-tool Backend, no
// global pointer) wrapped by ZKBoolContext (zk_context.h) and owned by
// ZKBoolSession (zk_session.h). It works purely in raw `block`s and never names
// the typed circuit layer, so it sits below ZKBoolContext / ZKInt in the include
// order. Party-specific gate and I/O behaviour is virtual on its own vtable: the
// prover /
// verifier subclasses implement and_block / not_block / feed_bits / reveal_bits.
class ZKBoolBase {
public:
  static constexpr int64_t CHECK_SZ = 1024 * 1024;

  int party;            // ALICE (prover) or BOB (verifier)

  // ---- Shared state (formerly OSTriple + ZKBoolBase) -----------
  block delta;          // Ferret global secret. Prover side just stores it.
  int64_t gid = 0;      // Number of AND gates issued.
  block pub_label[2];   // Labels for PUBLIC-input bits.

  // AND-gate triple buffer (ALICE-side: cleartext+MAC; BOB-side: keys only).
  int64_t check_cnt = 0;
  std::vector<block> andgate_out_buffer;
  std::vector<block> andgate_left_buffer;
  std::vector<block> andgate_right_buffer;

  // ---- f2k wire support (lazily initialised on first f2k op) ----------
  // The second wire type: authenticated F(2^128) values, sharing this
  // backend's Δ and its one Ferret. f2k_vole streams fresh authenticated
  // values for f2k_mul; the left/right val+mac buffers feed the batch
  // multiplication check (f2k_check_manage). The polynomial-product
  // variant lives in ZKPermProof, its sole caller. Conversion from bits
  // is a local Σ·Xⁱ map (same Δ), so only multiplication is interactive.
  bool f2k_ready = false;
  F2kVOLE<AuthValueF2k> *f2k_vole = nullptr;
  int64_t f2k_buffer_sz = 0;
  int64_t f2k_authval_cnt = 0, f2k_check_cnt = 0;
  std::vector<AuthValueF2k> f2k_auth_buffer;       // pre-drawn VOLE values
  std::vector<block> f2k_left_val, f2k_left_mac;
  std::vector<block> f2k_rght_val, f2k_rght_mac;
  // Dedicated VOLE buffer for f2k_input (committing a cleartext field
  // element). Kept separate from the mul buffer so f2k_check's omac_base
  // bookkeeping — which assumes the last check_cnt VOLE draws are all mul
  // outputs — stays undisturbed. Filled lazily, refilled when exhausted.
  std::vector<AuthValueF2k> f2k_in_buffer;
  int64_t f2k_in_cnt = 0;

  GaloisFieldPacking pack;
  BoolIO  *io  = nullptr;
  PRG prg;
  SilentFerret *ferret = nullptr;
  PolyProof  *polyproof = nullptr;

  // Worker count + pool for the parallel paths: SilentFerret's begin-time
  // expansion, the f2k VOLE, and the AND-gate batch check. 1 = single-threaded
  // (pool_ null), wire-identical to the prior path.
  int n_threads_ = 1;
  ThreadPool *pool_ = nullptr;

  // ---- Optional phase profiling (EMP_PROFILE=1), printed at teardown ----
  double prof_ferret_begin_us = 0.0;  // SilentFerret begin() prepay (COT setup)
  double prof_check_us = 0.0;         // andgate batch correctness checks

  // ---- Threaded COT prefetch (the bool analogue of arith's fill_vole_) ----
  // Every COT the engine consumes (gates, inputs, OPE checks, PolyProof) is
  // served FIFO from this buffer, which refills in bulk via the SilentFerret
  // wire-free *threaded* produce (next_chunks_parallel) instead of the serial
  // per-gate next_n(). Because it serves the same deterministic COT stream in
  // the same order, consumption is byte-identical to the old per-gate path
  // (at n_threads_==1 produce is the same serial next(); at >1 produce_range
  // yields the same COTs), so the wire transcript is unchanged.
  std::vector<block> cot_buf_;
  int64_t cot_pos_ = 0, cot_have_ = 0;

  // One fresh COT (hot path: one per AND gate).
  block draw_one_cot_() {
    if (cot_pos_ == cot_have_) cot_refill_();
    return cot_buf_[cot_pos_++];
  }
  // n fresh COTs, FIFO from the same stream (inputs / OPE / PolyProof).
  void draw_cot_(block *out, int64_t n) {
    int64_t done = 0;
    while (done < n) {
      if (cot_pos_ == cot_have_) cot_refill_();
      const int64_t take = std::min(n - done, cot_have_ - cot_pos_);
      memcpy(out + done, cot_buf_.data() + cot_pos_, (size_t)take * sizeof(block));
      cot_pos_ += take;
      done += take;
    }
  }
  void cot_refill_() {
    const int64_t chunk = ferret->chunk_size();
    const int64_t nch = (int64_t)cot_buf_.size() / chunk;
    ferret->next_chunks_parallel(cot_buf_.data(), nch, n_threads_);
    cot_pos_ = 0;
    cot_have_ = nch * chunk;
  }

  // Output-MAC accumulator. Hash + scratch buffer; finalize at teardown.
  Hash auth_hash;
  vector<block> auth_tmp;

  // ---- Lifecycle ------------------------------------------------------

  // `expected_cots` sizes the SilentFerret prepay: pass the number of COTs the
  // proof will draw (≈ AND gates + authenticated inputs + check overhead) and
  // begin() ships ALL correction traffic + malicious checks up front, so the
  // whole proof's COT consumption is wire-free. 0 (the default) uses the
  // per-round streaming begin() — safe for an unknown circuit size, at the cost
  // of one COT-correction burst per ~15M-COT round.
  ZKBoolBase(int p, BoolIO *io_, int64_t expected_cots = 0, int n_threads = 1)
      : party(p), io(io_), n_threads_(n_threads < 1 ? 1 : n_threads) {
    if (n_threads_ > 1) pool_ = new ThreadPool((size_t)n_threads_);
    // BoolIO inherits IOChannel publicly with the IOChannel subobject at
    // offset 0, so the cast is a no-op at runtime. Ferret now takes a
    // single IOChannel (post-unification with the other OT extensions).
    // n_threads sizes SilentFerret's begin()-time expansion pool.
    IOChannel *iochan = reinterpret_cast<IOChannel *>(io_);
    ferret = new SilentFerret(3 - p, iochan, /*malicious=*/true,
                              tuning::ferret_b13, nullptr, n_threads_);
    delta = ferret->Delta;           // Δ sampled in Ferret's ctor
    // One persistent SilentFerret streaming session for the whole proof. COTs
    // are drawn lazily, one per AND gate, straight from the streaming interface
    // (its leftover buffer); no separate pre-drawn COT pool is kept. Closed in
    // the destructor.
    auto _tferret = clock_start();
    if (expected_cots > 0) ferret->begin(expected_cots);
    else                   ferret->begin();
    prof_ferret_begin_us += time_from(_tferret);

    // Threaded COT prefetch buffer (gap #3): 128 chunks (~1M COTs) per refill,
    // produced wire-free across n_threads_ via SilentFerret::next_chunks_parallel.
    cot_buf_.resize((size_t)(128 * ferret->chunk_size()));

    // Buffers for the QuickSilver AND-gate batch check (left/right inputs +
    // output MAC, folded once per CHECK_SZ gates with an FS-derived chi). The
    // out buffer holds only the per-gate output MAC now — the fresh COT comes
    // from ferret->next_n() at gate time, not a pre-draw.
    andgate_out_buffer.resize(CHECK_SZ);
    andgate_left_buffer.resize(CHECK_SZ);
    andgate_right_buffer.resize(CHECK_SZ);

    // Public-input label table — known to both parties by design.
    // PRP(1) key, distinct from ZKFpExec's PRP(0), so the two public
    // outputs live in disjoint pseudorandom domains. Both bits start
    // LSB-cleared; subclass ctor flips bit-1 of pub_label[1] (prover)
    // or xors zdelta (verifier).
    pub_label[0] = makeBlock(0, 0);
    pub_label[1] = makeBlock(0, 1);
    PRP(makeBlock(0, 1)).permute_block(pub_label, 2);
    pub_label[0] = clear_lsb(pub_label[0]);
    pub_label[1] = clear_lsb(pub_label[1]);

    polyproof = new PolyProof(p, io_, ferret);
    // Route PolyProof's COT draws through the same FIFO buffer so the single
    // shared COT stream stays in order (otherwise its next_n would desync the
    // cursor the prefetch buffer has already advanced).
    polyproof->draw_cot = [this](block *o, int64_t n) { draw_cot_(o, n); };
  }

  virtual ~ZKBoolBase() {
    delete polyproof;   // PolyProof::batch_check draws COTs via next_n — session still open
    ferret->end();      // close the persistent streaming session (final round + chi-fold check)
    delete ferret;
    // f2k machinery (only allocated if some f2k op ran). The leftover
    // f2k batch check already happened in the subclass dtor — it needs
    // the live vtable and the open Ferret session — so here we only
    // free. delete nullptr is a no-op when f2k was unused.
    delete f2k_vole;
    delete pool_;
    if (getenv("EMP_PROFILE")) {
      fprintf(stderr,
              "[bool-prof p%d] ferret_begin=%.1fms andgate_check=%.1fms\n",
              party, prof_ferret_begin_us / 1000.0, prof_check_us / 1000.0);
    }
  }

  // ---- Helper bit ops -------------------------------------------------
  // The authenticated-bit format keeps the cleartext bit in the LSB and
  // the MAC in the upper 127 bits. clear_lsb / with_lsb / xor_delta_if
  // express that as named ops rather than ad-hoc choice[]/minusone tricks.
  static block clear_lsb(block b) {
    return b & makeBlock(0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFEULL);
  }
  // Branchless: bool → 0 or 1 directly.
  static block with_lsb(block b, bool v) {
    return clear_lsb(b) ^ makeBlock(0, static_cast<int64_t>(v));
  }
  // Branchless: -(int64_t)cond is 0 or all-ones; ANDing delta with that
  // mask gives delta or zero, which is then XORed unconditionally.
  block xor_delta_if(block b, bool cond) const {
    const int64_t m = -static_cast<int64_t>(cond);
    return b ^ (delta & makeBlock(m, m));
  }

  // ---- Gate surface (what ZKBoolContext's gate ops route to) ----------
  // Shared, non-virtual: public constants and XOR are party-agnostic.
  block public_block(bool b) const { return pub_label[b]; }
  block xor_block(block l, block r) const { return l ^ r; }
  uint64_t num_and() const { return gid; }

  // Party-specific gates / I-O, implemented by the prover / verifier subclass.
  virtual block and_block(block l, block r) = 0;
  virtual block not_block(block in) = 0;
  virtual void feed_bits(block *out, int from_party, const bool *in, size_t n) = 0;
  virtual void reveal_bits(bool *out, int to_party, const block *in, size_t n) = 0;

  // Commit `width` authenticated bits of `value`, ZERO-extended beyond bit 63,
  // into `out` via feed_bits. The f2k packing path uses this to commit a
  // cleartext field limb as prover-owned authenticated bits; it must NOT
  // sign-extend (which Int_T::constant would). Draws exactly `width` COTs.
  void authenticated_input_bits_zero_extend(block *out, int width,
                                            uint64_t value, int owner = ALICE) {
    auto b = std::make_unique<bool[]>((size_t)width);   // real bool[], no byte→bool cast
    for (int i = 0; i < width; ++i)
      b[(size_t)i] = (i < 64) ? (((value >> i) & 1) != 0) : false;
    feed_bits(out, owner, b.get(), (size_t)width);
  }

  // ---- AND-gate batch correctness check (single-threaded) ------------
  //
  // Derives a Fiat-Shamir seed from the io hash, runs the role-specific
  // reduction over the check_cnt buffered triples in one pass, then
  // hands off to the role-specific aggregator that does the network
  // exchange + compare. Fires once per CHECK_SZ buffered ANDs.
  void andgate_correctness_check_manage() {
    auto _tprof = clock_start();
    io->flush();
    block seed = io->io->get_digest();
    const int T = n_threads_;
    // Per-worker partials: ALICE (A0_t, A1_t) at sum[2t..2t+1]; BOB B_t at
    // sum[2t]. GF(2^128) reduce is linear over XOR, so XOR-combining the
    // per-range reduced partials is bit-identical to one serial pass.
    std::vector<block> sum(2 * (size_t)T, zero_block);
    if (T <= 1 || pool_ == nullptr) {
      andgate_correctness_check(sum.data(), 0, 0, check_cnt, seed);
    } else {
      const int64_t task_base = check_cnt / T;
      block *sum_ptr = sum.data();
      std::vector<std::future<void>> fut;
      int64_t start = 0;
      for (int t = 0; t < T - 1; ++t) {
        const int64_t s = start;
        const int idx = t;
        fut.push_back(pool_->enqueue([this, sum_ptr, idx, s, task_base, seed]() {
          andgate_correctness_check(sum_ptr, idx, s, task_base, seed);
        }));
        start += task_base;
      }
      andgate_correctness_check(sum.data(), T - 1, start, check_cnt - start,
                                seed);
      for (auto &f : fut) f.get();
    }
    block agg[2] = {zero_block, zero_block};
    for (int t = 0; t < T; ++t) {
      agg[0] = agg[0] ^ sum[2 * t];
      agg[1] = agg[1] ^ sum[2 * t + 1];
    }
    andgate_correctness_aggregate(agg);
    io->flush();
    prof_check_us += time_from(_tprof);
  }

  // Reduction over the buffered triples [start, start+task_n). ALICE writes the
  // (Δ⁰, Δ¹) coefficients into ret[2*thr_idx .. 2*thr_idx+1]; BOB writes its
  // check polynomial into ret[2*thr_idx]. Each worker re-derives its chi slice
  // by seeking PRG(chi_seed) to `start`, so the split is bit-identical to a
  // single serial pass.
  virtual void andgate_correctness_check(block *ret, int thr_idx, int64_t start,
                                         int64_t task_n, block chi_seed) = 0;

  // Trailing role-specific aggregation: ALICE packs + sends `A_star`,
  // BOB receives and verifies with cmpBlock.
  virtual void andgate_correctness_aggregate(block *sum) = 0;

  // ---- f2k wire ops ---------------------------------------------------
  //
  // Authenticated F(2^128) arithmetic on (val, mac) block pairs. Linear
  // ops (f2k_add_const) are local; f2k_mul is interactive and buffers its
  // triples for the batch check (f2k_check_manage), which fires once per
  // f2k_buffer_sz multiplications and again at teardown. (The degree-N
  // product variant lives in ZKPermProof.)

  // Allocate the f2k stream + buffers on first use; pure-bool proofs never
  // pay for it. The f2k VOLE shares this backend's Δ (BOB pins it); its
  // own inner Ferret keeps its wire bytes separate from the bit Ferret.
  void f2k_init() {
    if (f2k_ready) return;
    // SilentF2kVOLE is-a F2kVOLE (Svole base); the n_threads pool threads its
    // begin-time expansion. run()/set_delta dispatch virtually through the base
    // pointer, so the swap is transparent to the rest of the f2k machinery.
    f2k_vole = new SilentF2kVOLE<AuthValueF2k>(party, io, /*malicious=*/true,
                                               tuning::ferret_b10, n_threads_);
    if (party == BOB) f2k_vole->set_delta(ferret->Delta);
    f2k_buffer_sz = f2k_vole->chunk_aligned_buf_sz();
    f2k_auth_buffer.resize(f2k_buffer_sz);
    f2k_left_val.resize(f2k_buffer_sz);
    f2k_left_mac.resize(f2k_buffer_sz);
    f2k_rght_val.resize(f2k_buffer_sz);
    f2k_rght_mac.resize(f2k_buffer_sz);
    f2k_in_buffer.resize(f2k_buffer_sz);
    f2k_in_cnt = f2k_buffer_sz;        // sentinel: refill on first f2k_input
    f2k_ready = true;
    f2k_pre_buffer_refill();
  }

  // Commit a cleartext F(2^128) value as an authenticated wire (the f2k
  // analogue of authenticated-bit input). `v` is the cleartext on the
  // prover; the verifier's `v` argument is ignored and its returned val
  // lane is zero. Draws a fresh VOLE pair from the dedicated input buffer
  // and ships the masking difference so the wire carries `v` under the
  // shared Δ: mac_A == key_B ^ v·Δ. Party-agnostic signature.
  F2kAuthValue f2k_input(block v) {
    f2k_init();
    if (f2k_in_cnt == f2k_buffer_sz) {
      f2k_vole->run(f2k_in_buffer.data(), f2k_buffer_sz);
      f2k_in_cnt = 0;
    }
    AuthValueF2k r = f2k_in_buffer[f2k_in_cnt++];
    if (party == ALICE) {
      block diff = v ^ r.val;
      io->send_data(&diff, sizeof(block));
      return AuthValueF2k{ v, r.mac };
    }
    block diff;
    io->recv_data(&diff, sizeof(block));
    gfmul(delta, diff, &diff);
    return AuthValueF2k{ zero_block, r.mac ^ diff };
  }

  // Bulk-refill the pre-drawn VOLE buffer (one chunk-aligned run, so no
  // leftover) and reset the consume cursor.
  void f2k_pre_buffer_refill() {
    f2k_vole->run(f2k_auth_buffer.data(), f2k_buffer_sz);
    f2k_authval_cnt = 0;
  }

  // Pack a cleartext F(2^128) value v into the MAC layout the polynomial
  // product expects (Σ vᵢ·Xⁱ over the 128 bits of v, via the 65-bit
  // lo/hi SignedInt feed).
  block f2k_pack_v(block v) {
    uint64_t low  = _mm_extract_epi64(v, 0);
    uint64_t high = _mm_extract_epi64(v, 1);
    // Commit 65 zero-extended authenticated bits per limb. Only the low 64 are
    // packed, but the 65th is still drawn (one COT each) so Ferret consumption —
    // and the honest-path transcript — stays byte-identical to the old
    // SignedInt(65, ., ALICE) path this replaces.
    block lowbits[65], highbits[65], packbuf[128], m;
    authenticated_input_bits_zero_extend(lowbits, 65, low, ALICE);
    authenticated_input_bits_zero_extend(highbits, 65, high, ALICE);
    memcpy(packbuf,      lowbits,  64 * sizeof(block));
    memcpy(packbuf + 64, highbits, 64 * sizeof(block));
    pack.packing(&m, packbuf);
    return m;
  }

  // Bundle a (cleartext-field, mac) pair into an f2k wire. The cleartext
  // val is meaningful only on the prover; the verifier's val lane is
  // forced to zero. This is the bit→f2k conversion's output shape — the
  // mac is already Σ wireᵢ·Xⁱ — so callers can hand the same code path the
  // wire on both sides without a party branch.
  F2kAuthValue f2k_wire(block val, block mac) const {
    return AuthValueF2k{ party == ALICE ? val : zero_block, mac };
  }

  // Local linear f2k ops (no VOLE, no communication, party-agnostic): the
  // val/mac lanes are both linear in the wire, so scaling by a *public*
  // field constant or adding two wires is just the same gfmul / XOR on each
  // share. Used to collapse a multi-block element into one via a public
  // random linear combination Σ cⱼ·Bⱼ before the permutation product.
  F2kAuthValue f2k_mul_const(const F2kAuthValue &a, block c) const {
    F2kAuthValue r;
    gfmul(c, a.val, &r.val);
    gfmul(c, a.mac, &r.mac);
    return r;
  }
  F2kAuthValue f2k_add(const F2kAuthValue &a, const F2kAuthValue &b) const {
    return AuthValueF2k{ a.val ^ b.val, a.mac ^ b.mac };
  }

  // Role-specific f2k arithmetic + batch check (implemented by the
  // prover / verifier subclasses). Wires are F2kAuthValue (val, mac).
  virtual void f2k_add_const(F2kAuthValue &out, const F2kAuthValue &in,
                             block c) = 0;
  virtual void f2k_mul(F2kAuthValue &out, const F2kAuthValue &a,
                       const F2kAuthValue &b) = 0;
  virtual block f2k_mul_v(int64_t N, const block *vals) = 0;
  virtual void f2k_check_manage() = 0;
};

} // namespace emp

#include "emp-zk/emp-zk-bool/zk_bool_prover.h"
#include "emp-zk/emp-zk-bool/zk_bool_verifier.h"

#endif
