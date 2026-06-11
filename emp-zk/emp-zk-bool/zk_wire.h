#ifndef EMP_ZK_WIRE_H__
#define EMP_ZK_WIRE_H__

// ZKWire — the std::regular wire type the emp-zk-bool BooleanContext speaks.
// An emp-zk authenticated bit IS a single `block` (cleartext in the LSB, MAC in
// the upper 127 bits on the prover; the wire key on the verifier). The new
// emp-tool circuit value layer (Bit_T<Ctx>/Int_T<Ctx,N>) requires its Wire to
// be std::regular (default-constructible, copyable, equality-comparable), so we
// wrap the bare block in a thin struct with value equality.
//
// This is the LOWEST emp-zk-bool header: it names only `block` and pulls in no
// engine / context / typed-layer header, so it can sit under the engine in the
// include order (see the four-header split: zk_wire -> engine -> zk_context ->
// zk_types). The engine works in raw `block`; ZKWire appears only at the
// context/value boundary, where sizeof/alignof match `block` exactly (asserted
// in zk_context.h) so bulk feeds can memcpy.

#include "emp-tool/emp-tool.h"   // block, zero_block
#include <cstring>

namespace emp {

struct ZKWire {
    block label{};
    bool operator==(const ZKWire& o) const {
        return std::memcmp(&label, &o.label, sizeof(block)) == 0;
    }
    bool operator!=(const ZKWire& o) const { return !(*this == o); }
};

}  // namespace emp
#endif  // EMP_ZK_WIRE_H__
