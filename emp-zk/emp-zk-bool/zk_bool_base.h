#ifndef EMP_ZK_BOOL_BASE_H__
#define EMP_ZK_BOOL_BASE_H__

// emp-zk-bool's plug into the unified Backend* backend on emp-tool
// main. Single-threaded; one BoolIO* drives both the gate-level bool
// stream and Ferret's OT-extension data.
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
#include "emp-zk/emp-zk-bool/poly_prdt.h"

namespace emp {
using namespace std;

// The f2k wire type: an authenticated F(2^128) value (val, mac). Same
// storage as the sVOLE carrier; named for its role as a circuit wire.
using F2kAuthValue = AuthValueF2k;

class ZKBoolBase : public Backend {
public:
  static constexpr int64_t CHECK_SZ = 1024 * 1024;

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
  // values for f2k_mul; f2k_polyprdt handles the polynomial-product
  // variant (f2k_mul_poly); the left/right val+mac buffers feed the batch
  // multiplication check (f2k_check_manage). Conversion from bits is a
  // local Σ·Xⁱ map (same Δ), so only multiplication is interactive.
  bool f2k_ready = false;
  F2kVOLE<AuthValueF2k> *f2k_vole = nullptr;
  RamPolyPrdt<BoolIO> *f2k_polyprdt = nullptr;
  int64_t f2k_buffer_sz = 0;
  int64_t f2k_authval_cnt = 0, f2k_check_cnt = 0;
  std::vector<AuthValueF2k> f2k_auth_buffer;       // pre-drawn VOLE values
  std::vector<block> f2k_left_val, f2k_left_mac;
  std::vector<block> f2k_rght_val, f2k_rght_mac;

  GaloisFieldPacking pack;
  BoolIO  *io  = nullptr;
  PRG prg;
  Ferret  *ferret    = nullptr;
  PolyProof  *polyproof = nullptr;

  // Output-MAC accumulator. Hash + scratch buffer; finalize at teardown.
  Hash auth_hash;
  vector<block> auth_tmp;

  // ---- Lifecycle ------------------------------------------------------

  ZKBoolBase(int p, BoolIO *io_) : Backend(p), io(io_) {
    // BoolIO inherits IOChannel publicly with the IOChannel subobject at
    // offset 0, so the cast is a no-op at runtime. Ferret now takes a
    // single IOChannel (post-unification with the other OT extensions).
    IOChannel *iochan = reinterpret_cast<IOChannel *>(io_);
    ferret = new Ferret(3 - p, iochan, /*malicious=*/true);
    delta = ferret->Delta;           // Δ sampled in Ferret's ctor
    // Open one persistent Ferret streaming session for the whole proof;
    // all COTs are drawn via ferret->next_n(). This amortizes Ferret's
    // per-round end-work over the entire proof instead of paying it per
    // chunk (as repeated one-shot rcot() did). Closed in the destructor.
    ferret->begin();

    andgate_out_buffer.resize(CHECK_SZ);
    andgate_left_buffer.resize(CHECK_SZ);
    andgate_right_buffer.resize(CHECK_SZ);

    // Pre-draw the first batch of COTs into andgate_out_buffer. Each AND
    // gate consumes one slot (reads the fresh COT, then overwrites the slot
    // with the gate's output MAC for the eventual batch check), and the
    // batch boundary in auth_compute_and reloads the whole buffer after each
    // check. Drawing a full CHECK_SZ batch at once keeps the COT recv as one
    // burst, decoupled from the per-gate bit traffic flowing the other way.
    ferret->next_n(andgate_out_buffer.data(), CHECK_SZ);

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
    delete polyproof;   // PolyProof::batch_check draws COTs via next_n — session still open
    ferret->end();      // close the persistent streaming session (final round + chi-fold check)
    delete ferret;
    // f2k machinery (only allocated if some f2k op ran). The leftover
    // f2k batch check + polyprdt flush already happened in the subclass
    // dtor — they need the live vtable and the open Ferret session — so
    // here we only free. delete nullptr is a no-op when f2k was unused.
    delete f2k_polyprdt;
    delete f2k_vole;
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

  // ---- f2k wire ops ---------------------------------------------------
  //
  // Authenticated F(2^128) arithmetic on (val, mac) block pairs. Linear
  // ops (f2k_add_const) are local; f2k_mul / f2k_mul_poly are interactive
  // and buffer their triples for the batch check (f2k_check_manage), which
  // fires once per f2k_buffer_sz multiplications and again at teardown.

  // Allocate the f2k stream + buffers on first use; pure-bool proofs never
  // pay for it. The f2k VOLE shares this backend's Δ (BOB pins it); its
  // own inner Ferret keeps its wire bytes separate from the bit Ferret.
  void f2k_init() {
    if (f2k_ready) return;
    f2k_vole = new F2kVOLE<AuthValueF2k>(party, io, /*malicious=*/true,
                                         tuning::ferret_b10);
    if (party == BOB) f2k_vole->set_delta(ferret->Delta);
    f2k_buffer_sz = f2k_vole->chunk_aligned_buf_sz();
    f2k_auth_buffer.resize(f2k_buffer_sz);
    f2k_left_val.resize(f2k_buffer_sz);
    f2k_left_mac.resize(f2k_buffer_sz);
    f2k_rght_val.resize(f2k_buffer_sz);
    f2k_rght_mac.resize(f2k_buffer_sz);
    f2k_polyprdt = new RamPolyPrdt<BoolIO>(party, io, ferret);
    f2k_ready = true;
    f2k_pre_buffer_refill();
  }

  // Bulk-refill the pre-drawn VOLE buffer (one chunk-aligned run, so no
  // leftover) and reset the consume cursor.
  void f2k_pre_buffer_refill() {
    f2k_vole->run(f2k_auth_buffer.data(), f2k_buffer_sz);
    f2k_authval_cnt = 0;
  }

  // Pack a cleartext F(2^128) value v into the MAC layout the polynomial
  // product expects (Σ vᵢ·Xⁱ over the 128 bits of v, via the 65-bit
  // lo/hi Integer feed).
  block f2k_pack_v(block v) {
    uint64_t low  = _mm_extract_epi64(v, 0);
    uint64_t high = _mm_extract_epi64(v, 1);
    Integer lowInt(65, low, ALICE);
    Integer highInt(65, high, ALICE);
    block packbuf[128], m;
    memcpy(packbuf,      lowInt.bits.data(),  64 * sizeof(block));
    memcpy(packbuf + 64, highInt.bits.data(), 64 * sizeof(block));
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

  // Polynomial product over N f2k wires: out = ∏ inputs, with the MAC
  // committed through f2k_polyprdt's degree-N check. ALICE's f2k_mul_v
  // returns the cleartext product; BOB's returns zero.
  template <typename... Args>
  void f2k_mul_poly(F2kAuthValue &out, Args... args) {
    constexpr int N = sizeof...(args);
    static_assert(N >= 3 && N <= 5,
                  "f2k_mul_poly supports N=3, 4, 5 (matches polyPrdt3/4/5)");
    f2k_init();

    const F2kAuthValue in[N] = { args... };
    block vals[N], macs[N];
    for (int i = 0; i < N; ++i) {
      vals[i] = in[i].val;
      macs[i] = in[i].mac;
    }
    block v = f2k_mul_v(N, vals);
    block m = f2k_pack_v(v);
    f2k_polyprdt->template polyPrdtN<N>(vals, macs, m);
    out.val = v;
    out.mac = m;
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
