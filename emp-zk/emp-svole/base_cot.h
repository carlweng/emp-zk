#ifndef EMP_ZK_BASE_COT_H__
#define EMP_ZK_BASE_COT_H__

// Bootstrap COT used by SVoleF2k / VoleTriple. The class started life
// at emp-ot/ferret/base_cot.h on the v0.3.x emp-ot line, where it sat
// next to FerretCOT as the IKNP-bootstrapped seed-OT layer. emp-ot
// main folded that bootstrap into FerretCOT's own ctor and dropped
// the standalone class, but emp-zk's vole / vole-f2k still need a
// separate cot_gen handle. Carrying a port locally is the smallest
// change against the new line.
//
// Differences from the v0.3.x original:
//   - IKNP is no longer templated on IO; ctor takes `IOChannel*`.
//   - IKNP allocates state and samples Δ in its ctor; the base-OT
//     bootstrap fires lazily on first rcot_*_begin. There is no
//     public setup() — callers that want to override the ctor's
//     random Δ call set_delta(const bool*) before the first rcot_*.
//   - block_to_bool helper is gone from emp-tool; replaced by an
//     inline LSB-first bit extraction.

#include "emp-ot/emp-ot.h"
#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-svole/preot.h"

namespace emp {

template <typename IO> class BaseCot {
public:
  int party;
  block one, minusone;
  block ot_delta;
  IO *io;
  IKNP *iknp;
  bool malicious = false;

  BaseCot(int party, IO *io, bool malicious = false) {
    this->party = party;
    this->io = io;
    this->malicious = malicious;
    iknp = new IKNP(party, static_cast<IOChannel *>(io), malicious);
    minusone = makeBlock(0xFFFFFFFFFFFFFFFFLL, 0xFFFFFFFFFFFFFFFELL);
    one = makeBlock(0x0LL, 0x1LL);
  }

  ~BaseCot() { delete iknp; }

  static void block_to_bool_lsb(bool *out, block in) {
    const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&in);
    for (int i = 0; i < 128; ++i)
      out[i] = (bytes[i / 8] >> (i % 8)) & 1;
  }

  void cot_gen_pre(block deltain) {
    if (this->party == ALICE) {
      this->ot_delta = deltain;
      bool delta_bool[128];
      block_to_bool_lsb(delta_bool, ot_delta);
      iknp->set_delta(delta_bool);
    }
    // Receiver: no Δ to set; the bootstrap fires on first rcot_*_begin.
  }

  void cot_gen_pre() {
    if (this->party == ALICE) {
      // IKNP's ctor already sampled a random Δ with LSB=1 pinned —
      // reuse it instead of resampling. Mirror it into our own field
      // so cot_gen / check_cot can read the value without going
      // through iknp.
      this->ot_delta = iknp->Delta;
    }
  }

  void cot_gen(block *ot_data, int64_t size, bool *pre_bool = nullptr) {
    if (this->party == ALICE) {
      iknp->send_cot(ot_data, size);
      io->flush();
      for (int64_t i = 0; i < size; ++i)
        ot_data[i] = ot_data[i] & minusone;
    } else {
      PRG prg;
      // std::vector<bool> is bit-packed and lacks `.data() -> bool*`; use
      // unique_ptr<bool[]> for RAII without paying that abstraction cost.
      std::unique_ptr<bool[]> pre_bool_buf(new bool[size]);
      if (pre_bool && !malicious)
        memcpy(pre_bool_buf.get(), pre_bool, size);
      else
        prg.random_bool(pre_bool_buf.get(), size);
      iknp->recv_cot(ot_data, pre_bool_buf.get(), size);
      block ch[2];
      ch[0] = zero_block;
      ch[1] = makeBlock(0, 1);
      for (int64_t i = 0; i < size; ++i)
        ot_data[i] = (ot_data[i] & minusone) ^ ch[pre_bool_buf[i]];
    }
  }

  void cot_gen(OTPre<IO> *pre_ot, int64_t size, bool *pre_bool = nullptr) {
    std::vector<block> ot_data(size);
    if (this->party == ALICE) {
      iknp->send_cot(ot_data.data(), size);
      io->flush();
      for (int64_t i = 0; i < size; ++i)
        ot_data[i] = ot_data[i] & minusone;
      pre_ot->send_pre(ot_data.data(), ot_delta);
    } else {
      PRG prg;
      std::unique_ptr<bool[]> pre_bool_buf(new bool[size]);
      if (pre_bool && !malicious)
        memcpy(pre_bool_buf.get(), pre_bool, size);
      else
        prg.random_bool(pre_bool_buf.get(), size);
      iknp->recv_cot(ot_data.data(), pre_bool_buf.get(), size);
      block ch[2];
      ch[0] = zero_block;
      ch[1] = makeBlock(0, 1);
      for (int64_t i = 0; i < size; ++i)
        ot_data[i] = (ot_data[i] & minusone) ^ ch[pre_bool_buf[i]];
      pre_ot->recv_pre(ot_data.data(), pre_bool_buf.get());
    }
  }

  bool check_cot(block *data, int64_t len) {
    if (party == ALICE) {
      io->send_block(&ot_delta, 1);
      io->send_block(data, len);
      io->flush();
      return true;
    } else {
      std::vector<block> tmp(len);
      block ch[2];
      io->recv_block(ch + 1, 1);
      ch[0] = zero_block;
      io->recv_block(tmp.data(), len);
      for (int64_t i = 0; i < len; ++i)
        tmp[i] = tmp[i] ^ ch[getLSB(data[i])];
      return cmpBlock(tmp.data(), data, len);
    }
  }
};

} // namespace emp
#endif
