#ifndef EMP_ZK_CONTEXT_H__
#define EMP_ZK_CONTEXT_H__

// ZKBoolContext — the emp-tool BooleanContext adapter over the emp-zk-bool proof
// engine. It is the GATE ADAPTER in the three-part split (ZKBoolBase = raw
// protocol engine, ZKBoolContext = gate adapter, ZKBoolSession = public handle):
// it holds a non-owning ZKBoolBase* and forwards the four value-return gate ops
// to the engine's typed `*_block` methods. The typed circuit layer
// (Bit_T<ZKBoolContext>, Int_T<ZKBoolContext,N>) is built over this context, so
// it must be a complete BooleanContext BEFORE zk_types.h names those aliases —
// hence this header sits above the engine and below zk_types.h.

#include "emp-zk/emp-zk-bool/zk_bool_base.h"     // ZKBoolBase (+ prover/verifier)
#include "emp-tool/ir/context/concept.h"         // BooleanContext

namespace emp {

struct ZKBoolContext {
    using Wire = ZKWire;

    ZKBoolContext() = default;
    explicit ZKBoolContext(ZKBoolBase* eng) : eng_(eng) {}

    ZKBoolBase* engine() const { return eng_; }

    Wire public_bit(bool b)       { return ZKWire{ eng_->public_block(b) }; }
    Wire and_gate(Wire a, Wire b) { return ZKWire{ eng_->and_block(a.label, b.label) }; }
    Wire xor_gate(Wire a, Wire b) { return ZKWire{ eng_->xor_block(a.label, b.label) }; }
    Wire not_gate(Wire a)         { return ZKWire{ eng_->not_block(a.label) }; }

private:
    ZKBoolBase* eng_ = nullptr;
};

static_assert(BooleanContext<ZKBoolContext>,
              "ZKBoolContext must model emp::BooleanContext");
// The boundary helpers (zk_types.h) and bulk feeds memcpy between ZKWire[] and
// block[]; this makes that layout-compatible (a ZKWire is just its block).
static_assert(sizeof(ZKWire) == sizeof(block) && alignof(ZKWire) == alignof(block),
              "ZKWire must be layout-compatible with block");

}  // namespace emp
#endif  // EMP_ZK_CONTEXT_H__
