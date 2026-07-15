#ifndef EMP_ZK_SESSION_H__
#define EMP_ZK_SESSION_H__

// ZKBoolSession — the PUBLIC HANDLE for emp-zk-bool zero-knowledge proofs, and
// the emp-tool Session / DirectSession / SessionIO model for the ZK boolean
// context. It owns the proof engine (a ZKBoolProver on ALICE, ZKBoolVerifier on
// BOB), exposes the gate context via ctx(), and is the I/O boundary
// (input / reveal / input_bits / reveal_bits). There is NO global backend: every
// gadget receives a ZKBoolSession& explicitly and reaches the engine via engine().
//
// Lifecycle: the ctor sets up Ferret + the engine; finalize() runs the closing
// proof / network checks (leftover batch checks + the MAC-digest exchange that
// aborts via error() on a cheating prover) by destroying the engine. finalize()
// is explicit for a clear failure surface; the dtor calls it if you did not.
//
// Settlement (session contract, ir/session/session.h): this session settles AT
// FINALIZE — a value returned by reveal is PROVISIONAL until finalize() has run
// the closing checks; only then is the proof (and every earlier reveal) sound
// against a cheating prover. Do not act on revealed values across a trust
// boundary before finalize() succeeds.
//
// I/O surface (mirrors emp-sh2pc's session):
//   * input<V>/reveal<V> — fixed-width: V is an emp-tool WireValue (compile-time
//     width). Runtime-width: V is a RuntimeWidthValue (ZKUInt/ZKInt) and input
//     takes a trailing width — input<ZKUInt>(owner, value, width); reveal reads
//     the width off the value. ZKUInt reveals unsigned (uint64_t), ZKInt signed.
//   * input_bits/reveal_bits — width-agnostic raw Ctx::Wire I/O (the boundary an
//     IR-replay path such as execute_program speaks); use these instead of
//     reaching into engine().feed_bits/reveal_bits.
//   Only an ALICE witness or PUBLIC input is meaningful in boolean ZK; a BOB
//   input aborts. reveal recipient must be ALICE/BOB/PUBLIC.

#include "emp-zk/emp-zk-bool/zk_types.h"          // ZKBit/ZKInt + ZKBoolContext + engine
#include "emp-tool/ir/session/session_io.h"        // Session/DirectSession/SessionIO
#include "emp-tool/ir/wire_value.h"                // WireValue
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace emp {

class ZKBoolSession {
public:
    using ctx_t = ZKBoolContext;
    template <class V> using reveal_t = std::optional<typename V::clear_t>;

    // party = ALICE (prover) or BOB (verifier). `io` is caller-owned.
    // `expected_cots` (optional) sizes the SilentFerret prepay to the proof:
    // pass roughly the number of COTs it will draw (~ AND gates + authenticated
    // inputs + check overhead) and all COT correction traffic + malicious checks
    // ship once at setup, leaving the whole proof's COT consumption wire-free.
    // 0 (default) uses per-round streaming, safe for an unknown circuit size.
    // `n_threads` (optional, default 1) sizes the engine's worker pool: the
    // AND-gate batch check, the vectorized AND, threaded feeds, and the
    // PolyProof sums.
    // `cot_io` (optional): a SECOND caller-owned socket. When provided, the
    // SilentFerret runs on it in a background producer thread and the engine
    // draws COTs from a pipe while its own traffic stays on `io` (the bool
    // analogue of arith's background sVOLE); `expected_cots` is then ignored.
    // `cot_threads` (optional) sizes the COT producer's own worker pool
    // (Ferret / f2k-VOLE expansion + bulk produce) independently of
    // `n_threads`, so the two pools don't oversubscribe cores in background
    // mode; -1 (default) = same as n_threads.
    ZKBoolSession(BoolIO* io, int party, int64_t expected_cots = 0,
                  int n_threads = 1, BoolIO* cot_io = nullptr,
                  int cot_threads = -1) {
        if (party != ALICE && party != BOB)
            error("ZKBoolSession: party must be ALICE or BOB");
        if (io == nullptr) error("ZKBoolSession: io channel must not be null");
        if (cot_io == io)  error("ZKBoolSession: cot_io must be a distinct socket");
        if (party == ALICE) eng_ = new ZKBoolProver(io, expected_cots, n_threads,
                                                    cot_io, cot_threads);
        else                eng_ = new ZKBoolVerifier(io, expected_cots, n_threads,
                                                      cot_io, cot_threads);
        ctx_ = ZKBoolContext(eng_);
    }
    ~ZKBoolSession() { finalize(); }

    ZKBoolSession(const ZKBoolSession&) = delete;
    ZKBoolSession& operator=(const ZKBoolSession&) = delete;

    // Run the closing checks (engine dtor). Idempotent. A cheating prover aborts
    // here via error(); on success the session is spent and must not be reused.
    void finalize() { delete eng_; eng_ = nullptr; }

    int party() const { return eng_->party; }
    ctx_t& ctx() { return ctx_; }
    ZKBoolBase& engine() { return *eng_; }
    uint64_t num_and() const { return eng_->num_and(); }
    void flush() { eng_->io->flush(); }

    // ---- raw-bit I/O: the width-agnostic session boundary (IR replay, etc.) ----
    // Feed n cleartext bits owned by `owner` (ALICE witness or PUBLIC), returning
    // the authenticated wires. All typed input paths route through here.
    std::vector<ZKWire> input_bits(int owner, const bool* in, size_t n) {
        if (owner != ALICE && owner != PUBLIC)
            error("ZKBoolSession::input_bits: boolean ZK supports only ALICE or PUBLIC");
        std::vector<block> tmp(n);
        eng_->feed_bits(tmp.data(), owner, in, n);
        std::vector<ZKWire> w(n);
        for (size_t i = 0; i < n; ++i) w[i].label = tmp[i];
        return w;
    }
    // Open n wires to `recipient`; writes cleartext bits into `out` on a party
    // that learns them. Both parties must call in lockstep (the engine's branches
    // are party-symmetric only for a valid recipient — hence the guard).
    void reveal_bits(bool* out, int recipient, const ZKWire* w, size_t n) {
        check_recipient_(recipient);
        std::vector<block> blk(n);
        for (size_t i = 0; i < n; ++i) blk[i] = w[i].label;
        eng_->reveal_bits(out, recipient, blk.data(), n);
    }

    // ---- generic fixed-width WireValue I/O ----
    template <WireValue V>
    V input(int owner, const typename V::clear_t& clear) {
        static_assert(std::same_as<typename V::context_type, ctx_t>,
                      "ZKBoolSession::input<V>: V must be a value over ZKBoolContext");
        constexpr int W = V::width();
        const std::array<bool, (std::size_t)W> bits = V::encode(clear);   // stack; width is the type
        std::vector<ZKWire> w = input_bits(owner, bits.data(), (size_t)W);
        return V::from_wires(ctx_, w.data());
    }

    template <WireValue V>
    reveal_t<V> reveal(const V& v, int recipient) {
        static_assert(std::same_as<typename V::context_type, ctx_t>,
                      "ZKBoolSession::reveal<V>: V must be a value over ZKBoolContext");
#if EMP_CONTEXT_CHECKS
        if (v.context() != &ctx_)
            error("ZKBoolSession::reveal: value is bound to a different context");
#endif
        check_recipient_(recipient);
        constexpr int W = V::width();
        std::array<ZKWire, (std::size_t)W> w{};
        v.pack_wires(w.data());
        std::array<bool, (std::size_t)W> bb{};
        reveal_bits(bb.data(), recipient, w.data(), (size_t)W);
        if (!has_value_(recipient)) return std::nullopt;
        return std::optional<typename V::clear_t>(V::decode(bb.data()));
    }

    // ---- runtime-width WireValue I/O (RuntimeWidthValue) ----
    // Same statement boundary as the fixed input<V>/reveal<V>, but width is a
    // runtime argument (input) / read off the value (reveal). The codec rides
    // byte-bools (uint8_t 0/1); they are copied into real bool storage for the
    // engine boundary here — a uint8_t* is never reinterpreted as a bool*.
    template <RuntimeWidthValue V>
    V input(int owner, const typename V::clear_t& value, int width) {
        static_assert(std::same_as<typename V::context_type, ctx_t>,
                      "ZKBoolSession::input<V>: V must be a value over ZKBoolContext");
        if (width < 1)
            error("ZKBoolSession::input: runtime width must be >= 1");
        const std::vector<uint8_t> bits = V::encode(value, width);
        auto bb = std::make_unique<bool[]>((size_t)width);
        for (int i = 0; i < width; ++i) bb[(size_t)i] = (bits[(size_t)i] != 0);
        std::vector<ZKWire> w = input_bits(owner, bb.get(), (size_t)width);
        return V::from_wires(ctx_, w.data(), width);
    }

    template <RuntimeWidthValue V>
    reveal_t<V> reveal(const V& v, int recipient) {
        static_assert(std::same_as<typename V::context_type, ctx_t>,
                      "ZKBoolSession::reveal<V>: V must be a value over ZKBoolContext");
#if EMP_CONTEXT_CHECKS
        if (v.context() != &ctx_)
            error("ZKBoolSession::reveal: value is bound to a different context");
#endif
        check_recipient_(recipient);
        const int n = v.width();
        auto bb = std::make_unique<bool[]>((size_t)n);
        reveal_bits(bb.get(), recipient, v.data(), (size_t)n);
        if (!has_value_(recipient)) return std::nullopt;
        std::vector<uint8_t> buf((size_t)n);
        for (int i = 0; i < n; ++i) buf[(size_t)i] = (uint8_t)(bb[(size_t)i] ? 1 : 0);
        return std::optional<typename V::clear_t>(V::decode(buf.data(), n));
    }

private:
    bool has_value_(int recipient) const {
        return recipient == PUBLIC || recipient == eng_->party;
    }
    static void check_recipient_(int recipient) {
        if (recipient != ALICE && recipient != BOB && recipient != PUBLIC)
            error("ZKBoolSession::reveal: recipient must be ALICE, BOB, or PUBLIC");
    }
    ZKBoolBase* eng_ = nullptr;
    ZKBoolContext ctx_;
};

static_assert(Session<ZKBoolSession>);
static_assert(DirectSession<ZKBoolSession>);
static_assert(SessionIO<ZKBoolSession, UInt_T<ZKBoolContext, 32>>);
static_assert(SessionIO<ZKBoolSession, Bit_T<ZKBoolContext>>);
static_assert(RuntimeSessionIO<ZKBoolSession, ZKUInt>);
static_assert(RuntimeSessionIO<ZKBoolSession, ZKInt>);

}  // namespace emp
#endif  // EMP_ZK_SESSION_H__
