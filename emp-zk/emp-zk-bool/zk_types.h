#ifndef EMP_ZK_TYPES_H__
#define EMP_ZK_TYPES_H__

// The emp-zk-bool statement-boundary value types and the helpers that bridge
// them to the engine's raw `block` world. ZKBit / ZKInt are emp-tool circuit
// values built over ZKBoolContext; a user (and the gadgets, at their public
// surface) expresses statements with these, while the proof gadgets
// (polynomial / perm / f2k) keep operating on raw authenticated blocks.
//
// ZKInt is runtime-width (Int_T<Ctx,0>): width is a runtime value and it is
// intentionally NOT a fixed-width WireValue (no static width()/clear codec).
// Build/open it through ZKBoolSession's input_int / reveal_int, NOT
// Int_T::constant (which sign-extends above bit 63).
//
// Boundary helpers COPY the block out of / into a value (a ZKWire is layout-
// identical to a block — asserted in zk_context.h — but a reinterpret_cast view
// would not be strict-aliasing-safe, and this is not the hot path).

#include "emp-zk/emp-zk-bool/zk_context.h"
#include "emp-tool/circuits/typed.h"   // Bit_T / Int_T / UInt_T / value_traits
#include <vector>

namespace emp {

using ZKBit = Bit_T<ZKBoolContext>;
using ZKInt = Int_T<ZKBoolContext, 0>;   // runtime-width signed integer

// --- boundary helpers -------------------------------------------------------

// The authenticated block of a single bit.
inline block bit_block(const ZKBit& b) { return b.w.label; }

// Copy the per-bit authenticated blocks (LSB-first) out of a runtime-width int.
inline std::vector<block> int_blocks(const ZKInt& x) {
    const int n = x.width();
    std::vector<block> out((std::size_t)n);
    for (int i = 0; i < n; ++i) out[(std::size_t)i] = x.data()[i].label;
    return out;
}

inline int zk_int_width(const ZKInt& x) { return x.width(); }

// Rebuild a runtime-width int from raw authenticated blocks (LSB-first).
inline ZKInt zk_int_from_blocks(ZKBoolContext& ctx, const block* blk, int width) {
    std::vector<ZKWire> wires((std::size_t)width);
    for (int i = 0; i < width; ++i) wires[(std::size_t)i].label = blk[i];
    return ZKInt::from_wires(ctx, wires.data(), width);
}

}  // namespace emp
#endif  // EMP_ZK_TYPES_H__
