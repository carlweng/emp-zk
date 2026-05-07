#ifndef __EMP_BITIO_H__
#define __EMP_BITIO_H__
#include "emp-tool/emp-tool.h"

namespace emp {
// Bit-level IOChannel adapter for emp-zk-bool. De-templated alongside
// emp-tool main's switch from CRTP IOChannel<T> to a polymorphic
// virtual base — `io` is now an IOChannel*, send/recv go through
// the base's virtual dispatch, and consumers pass plain BoolIO* /
// IOChannel* without `<NetIO>` template baggage.
class BoolIO : public IOChannel {
public:
  IOChannel *io;
  Hash hash; // modelled as RO
  bool *buf;
  int ptr;
  bool sender;
  vector<unsigned char> tmp_arr;
  BoolIO(IOChannel *io, int sender) : io(io), sender(sender) {
    buf = new bool[NETWORK_BUFFER_SIZE2];
    if (sender)
      ptr = 0;
    else
      ptr = NETWORK_BUFFER_SIZE2;
  }
  ~BoolIO() {
    this->flush();
    delete[] buf;
  }
  void flush() override {
    if (sender) {
      if (ptr != 0) {
        bool data = true;
        while (ptr != 0)
          send_bit(data);
      }
    } else {
      ptr = NETWORK_BUFFER_SIZE2;
    }
    io->flush();
  }

  block get_hash_block() {
    block res[2];
    hash.digest((char *)res);
    return res[0];
  }

  void send_bit(bool data) {
    buf[ptr] = data;
    ptr++;
    if (ptr == NETWORK_BUFFER_SIZE2) {
      send_bool_raw(buf, NETWORK_BUFFER_SIZE2);
      ptr = 0;
    }
  }

  bool recv_bit() {
    if (ptr == NETWORK_BUFFER_SIZE2) {
      recv_bool_raw(buf, NETWORK_BUFFER_SIZE2);
      ptr = 0;
    }
    bool res = buf[ptr];
    ptr++;
    return res;
  }

  void send_data_internal(const void *data, size_t nbyte) override {
    if (ptr != 0)
      flush();
    io->send_data(data, nbyte);
  }

  void recv_data_internal(void *data, size_t nbyte) override {
    if (ptr != NETWORK_BUFFER_SIZE2)
      flush();
    io->recv_data(data, nbyte);
  }

  // Pack 8 bool-bytes (the LSB of each, the rest is required to be 0
  // by the bool[] storage convention) into one packed byte. PEXT does
  // it in one instruction on Haswell+; the // https://github.com/Forceflow/libmorton/issues/6
  // fallback walks the mask one bit at a time on older targets.
  static inline uint8_t pack_8bools(uint64_t eight_bytes) {
    constexpr uint64_t mask = 0x0101010101010101ULL;
#if defined(__BMI2__)
    return static_cast<uint8_t>(_pext_u64(eight_bytes, mask));
#else
    uint64_t tmp = 0, m = mask;
    for (uint64_t bb = 1; m != 0; bb += bb) {
      if (eight_bytes & m & -m)
        tmp |= bb;
      m &= (m - 1);
    }
    return static_cast<uint8_t>(tmp);
#endif
  }
  static inline uint64_t unpack_8bools(uint8_t packed) {
    constexpr uint64_t mask = 0x0101010101010101ULL;
#if defined(__BMI2__)
    return _pdep_u64(packed, mask);
#else
    uint64_t out = 0, m = mask;
    for (uint64_t bb = 1; m != 0; bb += bb) {
      if (packed & bb)
        out |= m & -m;
      m &= (m - 1);
    }
    return out;
#endif
  }

  void send_bool_raw(const bool *data, int length) {
    if (tmp_arr.size() < (size_t)length / 8)
      tmp_arr.resize(length / 8);

    auto *data64 = reinterpret_cast<const unsigned long long *>(data);
    int whole = length / 8;
    for (int i = 0; i < whole; ++i)
      tmp_arr[i] = pack_8bools(data64[i]);
    hash.put(tmp_arr.data(), whole);
    io->send_data(tmp_arr.data(), whole);
    counter += whole;

    if (8 * whole != length) {
      int rem = length - 8 * whole;
      hash.put(data + 8 * whole, rem);
      io->send_data(data + 8 * whole, rem);
      counter += rem;
    }
  }
  void recv_bool_raw(bool *data, int length) {
    if (tmp_arr.size() < (size_t)length / 8)
      tmp_arr.resize(length / 8);

    int whole = length / 8;
    io->recv_data(tmp_arr.data(), whole);
    hash.put(tmp_arr.data(), whole);

    auto *data64 = reinterpret_cast<unsigned long long *>(data);
    for (int i = 0; i < whole; ++i)
      data64[i] = unpack_8bools(tmp_arr[i]);

    if (8 * whole != length) {
      int rem = length - 8 * whole;
      io->recv_data(data + 8 * whole, rem);
      hash.put(data + 8 * whole, rem);
    }
  }
};
} // namespace emp
#endif // __UNIDIRIO_H__
