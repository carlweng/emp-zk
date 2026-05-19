#include "emp-ot/emp-ot.h"
#include "emp-ot/svole/fp_base_svole.h"
#include "emp-tool/emp-tool.h"

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
        std::cout << "base_svole error at " << i << std::endl;
        abort();
      }
    }
  }
}

void test_base_svole(NetIO *io, int party) {
  int test_n = 1024;
  std::vector<AV> pairs(test_n);

  Base_svole<AuthValueFp, NetIO> *svole;

  uint64_t Delta = 0;
  if (party == ALICE) {
    PRG prg;
    prg.random_data(&Delta, sizeof(uint64_t));
    Delta = mod(Delta);
    if (Delta == 0) Delta = 1;
    svole = new Base_svole<AuthValueFp, NetIO>(party, io, (__uint128_t)Delta);
  } else {
    svole = new Base_svole<AuthValueFp, NetIO>(party, io);
  }

  auto start = clock_start();
  if (party == ALICE) svole->triple_gen_send(pairs.data(), test_n);
  else                svole->triple_gen_recv(pairs.data(), test_n);
  std::cout << "base svole: " << time_from(start) * 1000 / test_n
            << " ns per entry" << std::endl;
  check_triple(io, Delta, pairs.data(), test_n);

  for (int i = 0; i < 10; ++i) {
    start = clock_start();
    if (party == ALICE) svole->triple_gen_send(pairs.data(), test_n);
    else                svole->triple_gen_recv(pairs.data(), test_n);
    std::cout << "base svole: " << time_from(start) * 1000 / test_n
              << " ns per entry" << std::endl;
    check_triple(io, Delta, pairs.data(), test_n);
  }
  std::cout << "pass check" << std::endl;

  delete svole;
}

int main(int argc, char **argv) {
  parse_party_and_port(argv, &party, &port);
  NetIO *io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

  std::cout << std::endl
            << "------------ BASE SVOLE ------------" << std::endl
            << std::endl;

  test_base_svole(io, party);

  delete io;
  return 0;
}
