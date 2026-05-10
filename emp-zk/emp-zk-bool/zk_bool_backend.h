#ifndef EMP_ZK_BOOL_BACKEND_H__
#define EMP_ZK_BOOL_BACKEND_H__

// emp-zk-bool's plug into the unified Backend* backend on emp-tool
// main. The v0.3.x design split the same machinery across two
// classes (ZKBoolCircExec for AND/XOR/NOT/public-label and
// ZKProver/ZKVerifier for input feeding + output revealing) wired
// up via the two static singletons CircuitExecution::circ_exec and
// ProtocolExecution::prot_exec. Backend collapses both singletons
// into one virtual interface.
//
// Layout:
//   - zk_bool_backend.h     — ZKBoolBackendBase: shared state + threading
//                             skeleton, with virtual hooks for the role-
//                             specific per-thread and aggregation work.
//   - zk_bool_backend_prv.h — ZKBoolBackendPrv: prover-only methods
//                             (auth_compute_and, authenticated_bits_input,
//                             verify_output, finalize_macs, hooks) and the
//                             Backend overrides routing to them.
//   - zk_bool_backend_ver.h — symmetric for the verifier.
//
// What used to be a separate OSTriple class is folded directly into
// the backend hierarchy: state goes on the base, prover-specific
// methods go in ZKBoolBackendPrv, verifier-specific in ZKBoolBackendVer.
// Removes the runtime party dispatch (`if (party == ALICE) … else …`)
// scattered through every method.

#include <emp-tool/emp-tool.h>

#include "emp-zk/emp-zk-bool/bool_io.h"
#include "emp-zk/emp-zk-bool/polynomial.h"

namespace emp {

class ZKBoolBackendBase : public Backend {
public:
  static constexpr int64_t CHECK_SZ = 1024 * 1024;

  // ---- Shared state (formerly OSTriple + ZKBoolBackendBase) -----------
  int threads;
  block delta;          // FerretCOT global secret. Prover side just stores it.
  int64_t gid = 0;      // Number of AND gates issued.
  block pub_label[2];   // Labels for PUBLIC-input bits.

  // AND-gate triple buffer (ALICE-side: cleartext+MAC; BOB-side: keys only).
  int check_cnt = 0;
  std::vector<block> andgate_out_buffer;
  std::vector<block> andgate_left_buffer;
  std::vector<block> andgate_right_buffer;

  GaloisFieldPacking pack;
  BoolIO  *io  = nullptr;
  BoolIO **ios = nullptr;
  PRG prg;
  FerretCOT  *ferret    = nullptr;
  ThreadPool *pool      = nullptr;
  PolyProof  *polyproof = nullptr;

  // Output-MAC accumulator. Hash + scratch buffer; finalize at teardown.
  Hash auth_hash;
  vector<block> auth_tmp;

  // Backend-owned RCOT buffer fed by the streaming API. The backend
  // holds one long-lived ferret session open from ctor to dtor;
  // take_rcot drains rcot_buf and refills via rcot_*_next when empty.
  // Other consumers that share `ferret` (PolyProof / F2kOSTriple /
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
        // side (BoolIO::flush() with ptr==NETWORK_BUFFER_SIZE2 + no
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

  ZKBoolBackendBase(int p, BoolIO **ios_, int threads_)
      : Backend(p), threads(threads_) {
    // BoolIO inherits IOChannel publicly with the IOChannel subobject at
    // offset 0, so the cast is a no-op at runtime. FerretCOT now takes a
    // single IOChannel (post-unification with the other OT extensions);
    // the per-thread IO array is still kept on this side and used by the
    // ThreadPool for the rest of the bool ZK protocol.
    IOChannel *iochan = reinterpret_cast<IOChannel *>(ios_[0]);
    ferret = new FerretCOT(3 - p, iochan, /*malicious=*/true, /*run_setup=*/true);
    ferret_is_sender = (p == BOB);   // ferret_party = 3-p; sender ⇔ ferret_party == ALICE
    delta = ferret->Delta;
    io = ios_[0];
    ios = ios_;
    pool = new ThreadPool(threads_);

    andgate_out_buffer.resize(CHECK_SZ);
    andgate_left_buffer.resize(CHECK_SZ);
    andgate_right_buffer.resize(CHECK_SZ);

    // Open the long-lived ferret RCOT session (ctor → dtor scope).
    // take_rcot and any other consumer (PolyProof, F2kOSTriple,
    // BaseSVoleF2k) drain from this single session via rcot_*_next.
    if (ferret_is_sender) ferret->rcot_send_begin();
    else                  ferret->rcot_recv_begin();

    // Burn one COT to align rcot internal state with the protocol.
    block tmp;
    take_rcot(&tmp, 1);

    // Public-input label table. Both bits start LSB-cleared; subclass
    // ctor flips bit-1 of pub_label[1] (prover) or xors zdelta (verifier).
    PRG label_prg(fix_key);
    label_prg.random_block(pub_label, 2);
    pub_label[0] = clear_lsb(pub_label[0]);
    pub_label[1] = clear_lsb(pub_label[1]);

    polyproof = new PolyProof(p, ios_[0], ferret);
  }

  ~ZKBoolBackendBase() override {
    // ~PolyProof runs batch_check, which still needs the open session.
    delete polyproof;
    if (ferret_is_sender) ferret->rcot_send_end();
    else                  ferret->rcot_recv_end();
    delete ferret;
    delete pool;
  }

  // ---- Helper bit ops -------------------------------------------------
  // The authenticated-bit format keeps the cleartext bit in the LSB and
  // the MAC in the upper 127 bits. clear_lsb / with_lsb / xor_delta_if
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

  uint64_t communication() {
    uint64_t res = 0;
    for (int i = 0; i < threads; ++i) res += ios[i]->counter;
    return res;
  }

  void sync() {
    for (int i = 0; i < threads; ++i) ios[i]->flush();
  }

  // ---- Threading skeleton for the AND-gate batch correctness check ---
  //
  // Common across both sides: derive a Fiat-Shamir seed from the io hash,
  // partition the check_cnt buffered triples across the worker pool, dispatch
  // each thread's slice, and then let the role-specific aggregator finalize
  // the protocol step. The per-thread work and the aggregation are virtual
  // hooks (see Prv / Ver). Fires once per CHECK_SZ buffered ANDs, so the
  // virtual-call overhead is negligible.
  void andgate_correctness_check_manage() {
    io->flush();
    block seed = io->get_hash_block();
    std::vector<std::future<void>> fut;

    std::vector<block> share_seed(threads);
    PRG(&seed).random_block(share_seed.data(), threads);

    // Distribute check_cnt tasks across `threads` workers. Workers
    // 0..threads-2 get task_base; the last takes whatever's left.
    // The leftover formula must be defined when task_base == 0
    // (i.e., check_cnt < threads).
    uint32_t task_base = check_cnt / threads;
    uint32_t leftover  = check_cnt - task_base * (threads - 1);
    uint32_t start = 0;
    std::vector<block> sum(2 * threads);
    for (int i = 0; i < threads - 1; ++i) {
      block *sum_p   = sum.data();
      block *seeds_p = share_seed.data();
      fut.push_back(
          pool->enqueue([this, sum_p, i, start, task_base, seeds_p]() {
            andgate_correctness_check(sum_p, i, start, task_base, seeds_p[i]);
          }));
      start += task_base;
    }
    andgate_correctness_check(sum.data(), threads - 1, start, leftover,
                              share_seed[threads - 1]);
    for (auto &f : fut) f.get();

    andgate_correctness_aggregate(sum.data());

    io->flush();
  }

  // Per-thread reduction over the check_cnt buffered triples.
  // ALICE collects the Δ⁰ and Δ¹ coefficients into ret[2*thr_i], ret[2*thr_i+1].
  // BOB collects ALICE's polynomial under his Δ into ret[thr_i].
  virtual void andgate_correctness_check(block *ret, int thr_i, uint32_t start,
                                          uint32_t task_n, block chi_seed) = 0;

  // Trailing role-specific aggregation: ALICE packs+sends `A_star`,
  // BOB receives and verifies with cmpBlock.
  virtual void andgate_correctness_aggregate(block *sum) = 0;
};

// Cross-module accessors. edabit / arith / ram-zk reach into the bool
// backend for state and helpers — the cast asserts in debug if the
// global `backend` isn't actually one of ours.
inline ZKBoolBackendBase *get_bool_backend() {
  return static_cast<ZKBoolBackendBase *>(backend);
}

} // namespace emp

#include "emp-zk/emp-zk-bool/zk_bool_backend_prv.h"
#include "emp-zk/emp-zk-bool/zk_bool_backend_ver.h"

#endif
