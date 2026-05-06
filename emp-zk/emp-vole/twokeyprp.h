#ifndef EMP_ZK_TWO_KEY_PRP_H__
#define EMP_ZK_TWO_KEY_PRP_H__

// Tree-expansion helper used by spfss_{sender,recver}. Lived at
// emp-ot/ferret/twokeyprp.h on the v0.3.x line; emp-ot main folded
// equivalent expansion into FerretCOT internals and dropped the
// standalone header. Carrying the small class locally is the
// minimum-change way to keep emp-zk's spfss compiling.

#include "emp-tool/emp-tool.h"

namespace emp {

// kappa -> 2 kappa PRG: G(k) = PRF_seed0(k) ^ k || PRF_seed1(k) ^ k.
class TwoKeyPRP {
public:
  AES_KEY aes_key[2];

  TwoKeyPRP(block seed0, block seed1) {
    AES_set_encrypt_key(seed0, aes_key);
    AES_set_encrypt_key(seed1, &aes_key[1]);
  }

  void node_expand_1to2(block *children, block parent) {
    block tmp[2];
    tmp[0] = children[0] = parent;
    tmp[1] = children[1] = parent;
    ParaEnc<2, 1>(tmp, aes_key);
    children[0] = children[0] ^ tmp[0];
    children[1] = children[1] ^ tmp[1];
  }

  void node_expand_2to4(block *children, block *parent) {
    block tmp[4];
    tmp[3] = children[3] = parent[1];
    tmp[1] = children[2] = parent[1];
    tmp[2] = children[1] = parent[0];
    tmp[0] = children[0] = parent[0];
    ParaEnc<2, 2>(tmp, aes_key);
    children[3] = children[3] ^ tmp[3];
    children[2] = children[2] ^ tmp[1];
    children[1] = children[1] ^ tmp[2];
    children[0] = children[0] ^ tmp[0];
  }

  void node_expand_4to8(block *children, block *parent) {
    block tmp[8];
    tmp[7] = children[7] = parent[3];
    tmp[3] = children[6] = parent[3];
    tmp[6] = children[5] = parent[2];
    tmp[2] = children[4] = parent[2];
    tmp[5] = children[3] = parent[1];
    tmp[1] = children[2] = parent[1];
    tmp[4] = children[1] = parent[0];
    tmp[0] = children[0] = parent[0];
    ParaEnc<2, 4>(tmp, aes_key);
    children[7] = children[7] ^ tmp[7];
    children[6] = children[6] ^ tmp[3];
    children[5] = children[5] ^ tmp[6];
    children[4] = children[4] ^ tmp[2];
    children[3] = children[3] ^ tmp[5];
    children[2] = children[2] ^ tmp[1];
    children[1] = children[1] ^ tmp[4];
    children[0] = children[0] ^ tmp[0];
  }
};

} // namespace emp
#endif
