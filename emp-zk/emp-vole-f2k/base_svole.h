#ifndef BASE_SVOLE_F2K_H__
#define BASE_SVOLE_F2K_H__
#include "emp-ot/emp-ot.h"

namespace emp {

template <typename IO> class BaseSVoleF2k {
public:
  int party;
  IO **ios;
  IO *io;
  FerretCOT *ferret = nullptr;
  block delta;

  GaloisFieldPacking pack;

  BaseSVoleF2k(int party, IO **ios, FerretCOT *ferret)
      : party(party), ios(ios), ferret(ferret) {

    if (party == BOB)
      delta = ferret->Delta;
    io = ios[0];
  }

  ~BaseSVoleF2k() {
  }

  void extend(block *val, block *mac, int num) {
    // Pull num*128 OTs out of the long-lived ferret session via
    // rcot_*_next chunks. Caller must have an open ferret session
    // (the bool backend opens one ctor->dtor; standalone tests have
    // to open it explicitly).
    std::vector<block> ferret_buffer((std::size_t)num * 128);
    const int64_t chunk = ferret->chunk_ots();
    std::vector<block> chunk_buf(chunk);
    int64_t needed = (int64_t)num * 128, got = 0;
    // ferret_party = 3-party; ferret is the OT-sender exactly when this side is BOB.
    const bool sender = (party == BOB);
    while (got < needed) {
      if (sender) ferret->rcot_send_next(chunk_buf.data());
      else        ferret->rcot_recv_next(chunk_buf.data());
      int64_t take = std::min(chunk, needed - got);
      std::memcpy(ferret_buffer.data() + got, chunk_buf.data(),
                  take * sizeof(block));
      got += take;
    }
    std::size_t j = 0;
    for (std::size_t i = 0; i < (std::size_t)num; ++i) {
      bool val_b[128];
      if (party == ALICE) {
        for (int k = 0; k < 128; ++k)
          val_b[k] = getLSB(ferret_buffer[j + k]);
        val[i] = bool_to_block(val_b);
      }
      pack.packing(mac + i, ferret_buffer.data() + j);
      j += 128;
    }
  }

  // DEBUG
  void check_correctness(block *val, block *mac, int num) {
    if (party == ALICE) {
      io->send_data(val, num * sizeof(block));
      io->send_data(mac, num * sizeof(block));
    } else {
      std::vector<block> vr(num), mr(num);
      io->recv_data(vr.data(), num * sizeof(block));
      io->recv_data(mr.data(), num * sizeof(block));
      for (int i = 0; i < num; ++i) {
        gfmul(vr[i], delta, &vr[i]);
        vr[i] = vr[i] ^ mac[i];
        if (memcmp(&vr[i], &mr[i], 16) != 0) {
          std::cout << i << std::endl;
          abort();
        }
      }
    }
  }
};
} // namespace emp
#endif
