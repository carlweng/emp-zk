#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
#include "emp-ot/svole/fp_base_svole.h"

using namespace emp;
using namespace std;

int party, port;

using AV = AuthValueFp;

void check_triple(NetIO *io, uint64_t delta, AV *pairs, int size) {
  if (party == ALICE) {
    io->send_data(&delta, sizeof(uint64_t));
    std::vector<uint64_t> macs(size);
    for (int i = 0; i < size; ++i) macs[i] = pairs[i].mac;
    io->send_data(macs.data(), size * sizeof(uint64_t));
  } else {
    uint64_t delta_recv;
    std::vector<uint64_t> mac_alice(size);
    io->recv_data(&delta_recv, sizeof(uint64_t));
    io->recv_data(mac_alice.data(), size * sizeof(uint64_t));
    for (int i = 0; i < size; ++i) {
      uint64_t tmp = mult_mod(delta_recv, pairs[i].val);
      tmp = add_mod(tmp, mac_alice[i]);
      if (tmp != pairs[i].mac) {
        std::cout << "LPN error at " << i << std::endl;
        abort();
      }
    }
  }
}

void test_lpn(NetIO *io, int party) {
  Base_svole<AuthValueFp> *svole;

  PRG prg;
  uint64_t Delta;
  prg.random_data_unaligned(&Delta, sizeof(uint64_t));
  Delta = mod(Delta);
  if (Delta == 0) Delta = 1;

  // test sizes reduced for github action
  int test_n = 1016832 / 2;
  int test_k = 1 << 17;   // power-of-2 for the unified Lpn
  AV *out  = new AV[test_n];
  AV *pre  = new AV[test_k];

  if (party == ALICE) {
    svole = new Base_svole<AuthValueFp>(party, io, zero_block, (__uint128_t)Delta);
    svole->triple_gen_send(out, test_n);
    svole->triple_gen_send(pre, test_k);
  } else {
    svole = new Base_svole<AuthValueFp>(party, io, zero_block);
    svole->triple_gen_recv(out, test_n);
    svole->triple_gen_recv(pre, test_k);
  }

  Lpn<AuthValueFp, 10> lpn(test_k);
  lpn.reseed(zero_block);
  auto start = clock_start();
  lpn.compute_slice(out, pre, test_n);
  check_triple(io, Delta, out, test_n);
  std::cout << "LPN: " << time_from(start) * 1000.0 / test_n << " ns per entry"
            << std::endl;

  delete[] out;
  delete[] pre;
  delete svole;
}

int main(int argc, char **argv) {
  parse_party_and_port(argv, &party, &port);
  NetIO *io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

  std::cout << std::endl
            << "------------ LPN ------------" << std::endl
            << std::endl;

  test_lpn(io, party);

  delete io;
  return 0;
}
