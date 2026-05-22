#ifndef EMP_ZK_RAM_GF_BASE_H__
#define EMP_ZK_RAM_GF_BASE_H__

// `GaloisFieldPacking::base[i] = X^i` (i.e. a block with bit i set,
// other bits zero) used to be exposed on emp-tool's
// GaloisFieldPacking. emp-tool main rewrote `packing()` to derive
// the basis on the fly via byte-level shifts and dropped the
// `base[]` field. ram-zk's per-coefficient inner-product code still
// wants random access to X^i, so we recompute the same array
// locally and return a stable pointer to it.

#include "emp-tool/emp-tool.h"

namespace emp {
using namespace std;

inline const block *ramzk_gf_base() {
  struct Init {
    block buf[128];
    Init() {
      for (int i = 0; i < 64; ++i)
        buf[i] = makeBlock(0, 1ULL << i);
      for (int i = 64; i < 128; ++i)
        buf[i] = makeBlock(1ULL << (i - 64), 0);
    }
  };
  static const Init holder;
  return holder.buf;
}

} // namespace emp
#endif
