#ifndef EMP_ZK_RAM_H__
#define EMP_ZK_RAM_H__

#include "emp-zk/emp-zk-bool/zk_set.h"
#include "emp-zk/emp-zk-bool/zk_perm_proof.h"

namespace emp {
using namespace std;

// Zero-knowledge memory via the "two shuffles" construction (Yang–Heath, "Two
// Shuffles Make a RAM", §4.3, Fig. 9). One class serves both read/write RAM
// and read-only ROM; `read_only` selects between them.
//
// Each access reads the old contents and writes back fresh contents — a store
// overwrites, a load (or any read-only access) rewrites the same value —
// recording a (address, value, time) read and a matching write into `perm`. A
// monotone public clock timestamps every write. Soundness rests on:
//   shuffle 1: reads ∼ writes            (every read references a real write)
//   shuffle 2: clock − t ∈ {1, …, T}     (that write happened in the past)
// Shuffle 1 alone forces every returned value to equal *some* past write to
// the same address; the monotone clock forbids cycles. For read/write memory
// that is not enough — a value can change, so a malicious prover could read a
// future write — and shuffle 2 (a ZKSet membership proof) pins each read to
// the *most recent* write (Invariant 2). For read-only memory the value never
// changes, so any past version is the right one: shuffle 2 is unnecessary and
// is skipped, recovering the single-permutation ROM cost.
//
// T is the maximum number of read()/write() accesses (not counting init or
// the teardown in check()); it bounds the timestamp range, and in read/write
// mode the freshness set {1, …, T}. Operation type is public, so no
// multiplexer multiplication is needed (Fig. 9's op·(w−old) term).
// Usage: init() once, read()/write() up to T times, check() once.
class ZKRam {
public:
  int party;
  bool read_only;
  int64_t index_sz, val_sz, T;
  int64_t time_sz;                 // holds timestamps 0 … T
  int64_t n = 0;                   // number of cells
  int64_t clock = 1;               // public; setup writes are time 0
  vector<uint64_t> mem;            // ALICE: current value per cell
  vector<uint64_t> last_t;         // ALICE: time of last write per cell
  ZKBoolSession &zk;               // owns the engine; source of input_int / reveal_int
  ZKBoolBase *bb;
  ZKPermProof perm;                // shuffle 1: reads ∼ writes
  ZKSet *diffs = nullptr;      // shuffle 2 (read/write only): clock−t in {1..T}
  vector<F2kAuthValue> elem_;

  ZKRam(ZKBoolSession &sess, int64_t index_sz, int64_t val_sz, int64_t T,
        bool read_only = false)
      : party(sess.party()), read_only(read_only), index_sz(index_sz),
        val_sz(val_sz), T(T), time_sz(ramzk_bits_for(T)), zk(sess),
        bb(&sess.engine()), perm(sess, index_sz + val_sz + time_sz) {
    if (!read_only)
      diffs = new ZKSet(sess, T, time_sz);
  }

  ~ZKRam() { delete diffs; }

  // Setup: commit the initial contents and emit a write (i, x[i], 0) per cell.
  void init(vector<ZKInt> &content) {
    n = (int64_t)content.size();
    if (party == ALICE) {
      mem.resize(n);
      last_t.assign(n, 0);
    }
    ZKInt time0 = zk.input_int(time_sz, 0, PUBLIC);
    for (int64_t i = 0; i < n; ++i) {
      if (party == ALICE)
        mem[i] = zk.reveal_int(content[i], ALICE).value_or(0);
      else
        zk.reveal_int(content[i], ALICE);
      emit_(/*toA=*/false, content[i],
            zk.input_int(index_sz, (uint64_t)i, PUBLIC), time0);
    }
  }

  ZKInt read(const ZKInt &index) { return access_(index, index, false); }

  void write(const ZKInt &index, const ZKInt &value) {
    if (read_only)
      error("ZKRam: write() on read-only memory");
    access_(index, value, true);
  }

  // Teardown: read every cell's final state, then run the shuffle(s).
  void check() {
    for (int64_t i = 0; i < n; ++i) {
      uint64_t v = (party == ALICE) ? mem[i] : 0;
      uint64_t t = (party == ALICE) ? last_t[i] : 0;
      emit_(/*toA=*/true, zk.input_int(val_sz, v, ALICE),
            zk.input_int(index_sz, (uint64_t)i, PUBLIC),
            zk.input_int(time_sz, t, ALICE));
    }
    perm.check_eq();
    if (!read_only)
      diffs->check();
  }

private:
  // One access. `value` is the new contents on a store; ignored on a load
  // (where we pass `index` as a harmless placeholder). Returns the old value.
  ZKInt access_(const ZKInt &index, const ZKInt &value, bool is_write) {
    uint64_t ci = zk.reveal_int(index, ALICE).value_or(0);
    // An index_sz-bit witness can exceed the cell count. Avoid a local OOB by
    // reading defaults for an out-of-range index and letting the closing
    // permutation check reject (the bogus read matches no write) — a
    // verifier-observed failure rather than a prover-side abort.
    const bool in_range = (ci < (uint64_t)n);
    uint64_t v_old = 0, t_old = 0;
    if (party == ALICE && in_range) {
      v_old = mem[ci];
      t_old = last_t[ci];
    }
    ZKInt old = zk.input_int(val_sz, v_old, ALICE);
    ZKInt time_old = zk.input_int(time_sz, t_old, ALICE);

    // shuffle 2: prove the last write to this cell is in the past.
    if (!read_only) {
      ZKInt diff = zk.input_int(time_sz, (uint64_t)clock, PUBLIC) - time_old;
      diffs->prove_member(diff);
    }

    // shuffle 1: read the old (addr, value, time), write back the new state.
    emit_(/*toA=*/true, old, index, time_old);
    ZKInt newv = is_write ? value : old;
    emit_(/*toA=*/false, newv, index,
          zk.input_int(time_sz, (uint64_t)clock, PUBLIC));

    if (party == ALICE) {
      uint64_t nv = is_write ? zk.reveal_int(value, ALICE).value_or(0) : v_old;
      if (in_range) { mem[ci] = nv; last_t[ci] = clock; }
    } else if (is_write) {
      zk.reveal_int(value, ALICE);   // keep the two parties' reveals in lockstep
    }
    ++clock;
    return old;
  }

  void emit_(bool toA, const ZKInt &value, const ZKInt &index,
             const ZKInt &time) {
    elem_.clear();
    ramzk_pack_record(bb, {&value, &index, &time}, elem_);
    if (toA)
      perm.add_A(elem_.data());
    else
      perm.add_B(elem_.data());
  }
};

// Read-only memory: ZKRam with shuffle 2 disabled. The value-chain (each read
// rewrites the same value under a fresh, monotone timestamp) anchors every
// read to the setup value without a freshness proof. T is the maximum number
// of read() lookups. read() returns the looked-up value; write() is illegal.
class ZKROM : public ZKRam {
public:
  ZKROM(ZKBoolSession &sess, int64_t index_sz, int64_t val_sz, int64_t T)
      : ZKRam(sess, index_sz, val_sz, T, /*read_only=*/true) {}
};

} // namespace emp
#endif // EMP_ZK_RAM_H__
