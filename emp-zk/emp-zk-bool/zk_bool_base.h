#ifndef EMP_ZK_BOOL_BASE_H__
#define EMP_ZK_BOOL_BASE_H__

// emp-zk-bool's plug into the unified Backend* backend on emp-tool
// main. Single-threaded; one BoolIO* drives both the gate-level bool
// stream and FerretCOT's OT-extension data.
//
// Layout:
//   - zk_bool_base.h     — ZKBoolBase: shared state + the AND-gate
//                          batch correctness-check entry point, with
//                          virtual hooks for the role-specific check
//                          and aggregator.
//   - zk_bool_prover.h   — ZKBoolProver: ALICE-side methods
//                          (auth_compute_and, authenticated_bits_input,
//                          verify_output, finalize_macs, hooks) and the
//                          Backend overrides routing to them.
//   - zk_bool_verifier.h — symmetric for the verifier.
//
// What used to be a separate OSTriple class is folded directly into
// the backend hierarchy: state goes on the base, prover-specific
// methods go in ZKBoolProver, verifier-specific in ZKBoolVerifier.
// Removes the runtime party dispatch (`if (party == ALICE) … else …`)
// scattered through every method.

#include <emp-tool/emp-tool.h>

#include "emp-zk/emp-zk-bool/bool_io.h"
#include "emp-zk/emp-zk-bool/polynomial.h"

namespace emp {

class ZKBoolBase : public Backend {
public:
  static constexpr int64_t CHECK_SZ = 1024 * 1024;

  // ---- Shared state (formerly OSTriple + ZKBoolBase) -----------
  block delta;          // FerretCOT global secret. Prover side just stores it.
  int64_t gid = 0;      // Number of AND gates issued.
  block pub_label[2];   // Labels for PUBLIC-input bits.

  // AND-gate triple buffer (ALICE-side: cleartext+MAC; BOB-side: keys only).
  int64_t check_cnt = 0;
  std::vector<block> andgate_out_buffer;
  std::vector<block> andgate_left_buffer;
  std::vector<block> andgate_right_buffer;

  GaloisFieldPacking pack;
  BoolIO  *io  = nullptr;
  PRG prg;
  FerretCOT  *ferret    = nullptr;
  PolyProof  *polyproof = nullptr;

  // Output-MAC accumulator. Hash + scratch buffer; finalize at teardown.
  Hash auth_hash;
  vector<block> auth_tmp;

  // Backend-owned RCOT buffer fed by the streaming API. The backend
  // holds one long-lived ferret session open from ctor to dtor;
  // take_rcot drains rcot_buf and refills via rcot_*_next when empty.
  // Other consumers that share `ferret` (PolyProof / RamOSTriple /
  // BaseSVoleF2k) call rcot_*_next directly with their own scratch.
  //
  // Refill granularity: each refill calls rcot_*_next K times in a
  // row, filling K * chunk_ots() OTs (1 chunk = 1 cGGM tree). Larger
  // K cuts the take_rcot dispatch frequency by K but proportionally
  // grows the buffer: at b13, K=512 → ~67 MiB. NetIO already
  // auto-batches the per-tree corrections in its 32 KiB send buffer,
  // so K mostly affects local dispatch, not wire traffic.
  static constexpr int64_t kRcotRefillK = 1 << 9;
  std::vector<block> rcot_buf;
  int64_t rcot_pos = 0, rcot_avail = 0;
  // ferret was constructed with party = (3 - p), so ferret_is_sender
  // flips the prover/verifier party labels. Captured once at ctor to
  // avoid threading the inversion into every dispatch site.
  bool ferret_is_sender;

  void take_rcot(block *out, int64_t n) {
    while (n > 0) {
      if (rcot_avail == 0) {
        const int64_t chunk = ferret->chunk_ots();
        const int64_t want = chunk * kRcotRefillK;
        if ((int64_t)rcot_buf.size() < want) rcot_buf.resize(want);
        for (int64_t k = 0; k < kRcotRefillK; ++k) {
          block *slot = rcot_buf.data() + k * chunk;
          if (ferret_is_sender) ferret->rcot_send_next(slot);
          else                  ferret->rcot_recv_next(slot);
        }
        // Eager flush: push any OT-extension bytes still in NetIO's
        // send_buf out to the wire so the receiver doesn't stall
        // waiting for a future refill or run_end. No-op on the recv
        // side (BoolIO::flush() with ptr==NETWORK_STAGING_BUFFER_SIZE + no
        // pending sends).
        io->flush();
        rcot_pos = 0;
        rcot_avail = want;
      }
      int64_t take = std::min(n, rcot_avail);
      std::memcpy(out, rcot_buf.data() + rcot_pos, take * sizeof(block));
      rcot_pos += take;
      rcot_avail -= take;
      out += take;
      n -= take;
    }
  }

  // ---- Lifecycle ------------------------------------------------------

  ZKBoolBase(int p, BoolIO *io_) : Backend(p), io(io_) {
    // BoolIO inherits IOChannel publicly with the IOChannel subobject at
    // offset 0, so the cast is a no-op at runtime. FerretCOT now takes a
    // single IOChannel (post-unification with the other OT extensions).
    IOChannel *iochan = reinterpret_cast<IOChannel *>(io_);
    ferret = new FerretCOT(3 - p, iochan, /*malicious=*/true);
    ferret_is_sender = (p == BOB);   // ferret_party = 3-p; sender ⇔ ferret_party == ALICE
    delta = ferret->Delta;           // Δ sampled in FerretCOT's ctor; bootstrap fires lazily on first rcot_*_begin

    andgate_out_buffer.resize(CHECK_SZ);
    andgate_left_buffer.resize(CHECK_SZ);
    andgate_right_buffer.resize(CHECK_SZ);

    // Open the long-lived ferret RCOT session (ctor → dtor scope).
    // take_rcot and any other consumer (PolyProof, RamOSTriple,
    // BaseSVoleF2k) drain from this single session via rcot_*_next.
    if (ferret_is_sender) ferret->rcot_send_begin();
    else                  ferret->rcot_recv_begin();

    // Burn one COT to align rcot internal state with the protocol.
    block tmp;
    take_rcot(&tmp, 1);

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
  }

  ~ZKBoolBase() override {
    // ~PolyProof runs batch_check, which still needs the open session.
    delete polyproof;
    if (ferret_is_sender) ferret->rcot_send_end();
    else                  ferret->rcot_recv_end();
    delete ferret;
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

  // ---- Backend overrides shared by both sides -------------------------

  size_t wire_bytes() const override { return sizeof(block); }

  void public_label(void *o, bool b) override {
    *static_cast<block *>(o) = pub_label[b];
  }
  void xor_gate(void *o, const void *l, const void *r) override {
    *static_cast<block *>(o) =
        *static_cast<const block *>(l) ^ *static_cast<const block *>(r);
  }
  uint64_t num_and() override { return gid; }

  // ---- Other shared utilities ----------------------------------------

  uint64_t communication() { return io->counter; }
  void sync() { io->flush(); }

  // ---- AND-gate batch correctness check (single-threaded) ------------
  //
  // Derives a Fiat-Shamir seed from the io hash, runs the role-specific
  // reduction over the check_cnt buffered triples in one pass, then
  // hands off to the role-specific aggregator that does the network
  // exchange + compare. Fires once per CHECK_SZ buffered ANDs.
  void andgate_correctness_check_manage() {
    io->flush();
    block seed = io->get_hash_block();
    // ALICE writes (A0, A1) into sum[0..1]; BOB writes B into sum[0].
    block sum[2] = { zero_block, zero_block };
    andgate_correctness_check(sum, check_cnt, seed);
    andgate_correctness_aggregate(sum);
    io->flush();
  }

  // Reduction over the buffered triples. ALICE writes the (Δ⁰, Δ¹)
  // coefficients into ret[0..1]; BOB writes its check polynomial into
  // ret[0].
  virtual void andgate_correctness_check(block *ret, int64_t task_n,
                                         block chi_seed) = 0;

  // Trailing role-specific aggregation: ALICE packs + sends `A_star`,
  // BOB receives and verifies with cmpBlock.
  virtual void andgate_correctness_aggregate(block *sum) = 0;
};

// Cross-module accessors. edabit / arith / ram-zk reach into the bool
// backend for state and helpers — the cast asserts in debug if the
// global `backend` isn't actually one of ours.
inline ZKBoolBase *get_bool_backend() {
  return static_cast<ZKBoolBase *>(backend);
}

} // namespace emp

#include "emp-zk/emp-zk-bool/zk_bool_prover.h"
#include "emp-zk/emp-zk-bool/zk_bool_verifier.h"

#endif
