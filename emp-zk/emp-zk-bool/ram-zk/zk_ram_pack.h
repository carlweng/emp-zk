#ifndef EMP_ZK_RAM_PACK_H__
#define EMP_ZK_RAM_PACK_H__

#include "emp-zk/emp-zk-bool/gf_base.h"
#include "emp-zk/emp-zk-bool/zk_bool_base.h"

namespace emp {
using namespace std;

// Pack a record — the concatenation (in order) of the authenticated bits of
// `parts` — into ⌈total/128⌉ f2k wires appended to `out`. Each 128-bit block
// places component bit i at field position Xⁱ (Σ·Xⁱ over ramzk_gf_base), so
// two records with identical cleartext collapse to identical field values
// regardless of whether their bits were committed as public or private wires.
// This is the bit→f2k conversion shared by the permutation-based RAM/ROM/set
// data structures (Yang–Heath, "Two Shuffles Make a RAM").
inline void ramzk_pack_record(ZKBoolBase *bb,
                              std::initializer_list<const Integer *> parts,
                              vector<F2kAuthValue> &out) {
  vector<block> wire;
  for (const Integer *p : parts) {
    const block *b = (const block *)p->bits.data();
    wire.insert(wire.end(), b, b + p->bits.size());
  }
  const int64_t total = (int64_t)wire.size();
  const int64_t mblk = (total + 127) / 128;
  const block *gf = ramzk_gf_base();
  for (int64_t blk = 0; blk < mblk; ++blk) {
    const int64_t lo = blk * 128;
    const int64_t k = std::min<int64_t>(128, total - lo);
    block mac;
    vector_inn_prdt_sum_red(&mac, &wire[lo], gf, (int)k);
    block val = zero_block;                     // cleartext field elt (ALICE)
    for (int64_t t = 0; t < k; ++t)
      if (getLSB(wire[lo + t])) val = val ^ gf[t];
    out.push_back(bb->f2k_wire(val, mac));      // f2k_wire zeroes BOB's val
  }
}

// Bit width needed to hold any value in [0, hi]: the smallest b with 2^b > hi.
inline int64_t ramzk_bits_for(int64_t hi) {
  int64_t b = 1;
  while ((int64_t(1) << b) <= hi)
    ++b;
  return b;
}

} // namespace emp
#endif // EMP_ZK_RAM_PACK_H__
