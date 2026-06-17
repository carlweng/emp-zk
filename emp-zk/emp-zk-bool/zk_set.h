#ifndef EMP_ZK_SET_H__
#define EMP_ZK_SET_H__

#include "emp-zk/emp-zk-bool/zk_perm_proof.h"

namespace emp {
using namespace std;

// Zero-knowledge set with membership queries (Yang–Heath, "Two Shuffles Make
// a RAM", §4.2) — the ℓ=0 specialization of the version-chain ROM. The set is
// the public range {1, …, T}; prove_member(v) proves the committed value v is
// one of those elements. A query that names a value outside the range cannot
// be chained back to a setup write, so the closing reads ∼ writes permutation
// fails (Remark 1), which is exactly the proof of membership.
//
// Each record is (element, version) packed into one f2k wire; versions act as
// per-element counters so distinct queries to the same element chain rather
// than collide. This is the freshness check for the read/write RAM: the RAM
// proves clock − t ∈ {1, …, T} for every access.
class ZKSet {
public:
  int party;
  int64_t T;             // set is {1, …, T}
  int64_t elem_sz;       // bit width of an element (and of queried values)
  int64_t ver_sz;        // version field; per-element queries ≤ T
  vector<uint64_t> ver;  // ALICE: latest version per element, indexed by value
  ZKBoolSession &zk;     // owns the engine; source of runtime input/reveal
  ZKBoolBase *bb;
  ZKPermProof perm;      // A = reads (queries + teardown), B = writes (setup)
  vector<F2kAuthValue> elem_;

  ZKSet(ZKBoolSession &sess, int64_t T, int64_t elem_sz)
      : party(sess.party()), T(T), elem_sz(elem_sz), ver_sz(ramzk_bits_for(T)),
        zk(sess), bb(&sess.engine()), perm(sess, elem_sz + ver_sz) {
    if (party == ALICE)
      ver.assign((size_t)T + 1, 0);
    // Setup: write (e, version 0) for every element of the public range.
    ZKUInt ver0 = zk.input<ZKUInt>(PUBLIC, 0, ver_sz);
    for (int64_t e = 1; e <= T; ++e)
      emit_(/*toA=*/false, zk.input<ZKUInt>(PUBLIC, (uint64_t)e, elem_sz), ver0);
  }

  // Prove that the committed value v ∈ {1, …, T}. Appends a (v, ver) read and
  // a (v, ver+1) write, mirroring a ROM lookup of key v.
  void prove_member(const ZKUInt &v) {
    uint64_t e = zk.reveal(v, ALICE).value_or(0);
    // ver is indexed by the queried value (size T+1). An out-of-range witness
    // reads a default version (no local OOB) and is rejected by the closing perm
    // check — a query outside {1..T} chains to no setup write — rather than
    // aborting the prover here.
    const bool in_range = (e <= (uint64_t)T);
    uint64_t vv = (party == ALICE && in_range) ? ver[e] : 0;
    ZKUInt ver_old = zk.input<ZKUInt>(ALICE, vv, ver_sz);
    emit_(/*toA=*/true, v, ver_old);                                    // read
    emit_(/*toA=*/false, v, ver_old + zk.input<ZKUInt>(PUBLIC, 1, ver_sz)); // write
    if (party == ALICE && in_range)
      ver[e] = vv + 1;
  }

  // Teardown: read every element's final version, then prove reads ∼ writes.
  void check() {
    for (int64_t e = 1; e <= T; ++e) {
      uint64_t vv = (party == ALICE) ? ver[e] : 0;
      emit_(/*toA=*/true, zk.input<ZKUInt>(PUBLIC, (uint64_t)e, elem_sz),
            zk.input<ZKUInt>(ALICE, vv, ver_sz));
    }
    perm.check_eq();
  }

private:
  void emit_(bool toA, const ZKUInt &element, const ZKUInt &version) {
    elem_.clear();
    ramzk_pack_record(bb, {&element, &version}, elem_);
    if (toA)
      perm.add_A(elem_.data());
    else
      perm.add_B(elem_.data());
  }
};

} // namespace emp
#endif // EMP_ZK_SET_H__
