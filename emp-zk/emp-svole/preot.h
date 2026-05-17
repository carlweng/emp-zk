#ifndef _PRE_OT__
#define _PRE_OT__
#include "emp-ot/emp-ot.h"
#include "emp-tool/emp-tool.h"
namespace emp {

template <typename IO> class OTPre {
public:
  IO *io;
  std::vector<block> pre_data;
  // bool[] (not std::vector<bool>) because we need real bool* pointer
  // arithmetic and memcpy semantics — vector<bool> is bit-packed and
  // fails on both. unique_ptr gives the same RAII shape as vector.
  std::unique_ptr<bool[]> bits;
  int64_t n;
  vector<block *> pointers;
  vector<const bool *> choices;
  vector<const block *> pointers0;
  vector<const block *> pointers1;

  CCRH ccrh;
  int64_t length, count;
  block Delta;
  OTPre(IO *io, int64_t length, int64_t times)
      : io(io), n(length * times), length(length), count(0) {
    pre_data.resize(2 * n);
    bits.reset(new bool[n]);
  }

  void send_pre(block *data, block in_Delta) {
    Delta = in_Delta;
    ccrh.Hn(pre_data.data(), data, n, pre_data.data() + n);
    xorBlocks_arr(pre_data.data() + n, data, Delta, n);
    ccrh.Hn(pre_data.data() + n, pre_data.data() + n, n);
  }

  void recv_pre(block *data, bool *b) {
    memcpy(bits.get(), b, n);
    ccrh.Hn(pre_data.data(), data, n);
  }

  void recv_pre(block *data) {
    for (int64_t i = 0; i < n; ++i)
      bits[i] = getLSB(data[i]);
    ccrh.Hn(pre_data.data(), data, n);
  }

  void choices_sender() {
    io->recv_data(bits.get() + count, length);
    count += length;
  }

  void choices_recver(const bool *b) {
    for (int64_t i = 0; i < length; ++i) {
      bits[count + i] = (b[i] != bits[count + i]);
    }
    io->send_data(bits.get() + count, length);
    count += length;
  }

  void reset() { count = 0; }

  void send(const block *m0, const block *m1, int64_t length, IO *io2, int64_t s) {
    block pad[2];
    int64_t k = s * length;
    for (int64_t i = 0; i < length; ++i) {
      if (!bits[k]) {
        pad[0] = m0[i] ^ pre_data[k];
        pad[1] = m1[i] ^ pre_data[k + n];
      } else {
        pad[0] = m0[i] ^ pre_data[k + n];
        pad[1] = m1[i] ^ pre_data[k];
      }
      ++k;
      io2->send_block(pad, 2);
    }
  }

  void recv(block *data, const bool *b, int64_t length, IO *io2, int64_t s) {
    int64_t k = s * length;
    block pad[2];
    for (int64_t i = 0; i < length; ++i) {
      io2->recv_block(pad, 2);
      int ind = b[i] ? 1 : 0;
      data[i] = pre_data[k] ^ pad[ind];
      ++k;
    }
  }
};
} // namespace emp
#endif // _PRE_OT__
