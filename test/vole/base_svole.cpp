#include "emp-zk/emp-vole/base_svole.h"
#include "emp-tool/emp-tool.h"

using namespace emp;
using namespace std;

int party, port;

void check_triple(NetIO *io, uint64_t x, uint64_t *y, int size) {
  io->send_data(&x, sizeof(uint64_t));
  io->send_data(y, size * sizeof(uint64_t));
  io->flush();
}

void check_triple(NetIO *io, __uint128_t *y, int size) {
  uint64_t delta;
  uint64_t *k = new uint64_t[size];
  io->recv_data(&delta, sizeof(uint64_t));
  io->recv_data(k, size * sizeof(uint64_t));
  for (int i = 0; i < size; ++i) {
    __uint128_t tmp = mod(delta * (y[i] >> 64), pr);
    tmp = mod(tmp + k[i], pr);
    if (tmp != (y[i] & 0xFFFFFFFFFFFFFFFFLL)) {
      std::cout << "base_svole error" << std::endl;
      abort();
    }
  }
  delete[] k;
}

void test_base_svole(NetIO *io, int party) {
  int test_n = 1024;

  Base_svole<NetIO> *svole;

  uint64_t Delta;
  if (party == ALICE) {
    PRG prg;
    prg.random_data(&Delta, sizeof(uint64_t));
    Delta = mod(Delta);

    svole = new Base_svole<NetIO>(party, io, Delta);
  } else {
    svole = new Base_svole<NetIO>(party, io);
  }

  // test single
  auto start = clock_start();
  if (party == ALICE) {
    uint64_t *mac = new uint64_t[test_n];
    svole->triple_gen_send(mac, test_n);
    check_triple(io, Delta, mac, test_n);
    delete[] mac;
  } else {
    __uint128_t *mac = new __uint128_t[test_n];
    svole->triple_gen_recv(mac, test_n);
    std::cout << "base svole: " << time_from(start) * 1000 / test_n
              << " ns per entry" << std::endl;
    check_triple(io, mac, test_n);
    delete[] mac;
  }

  for (int i = 0; i < 10; ++i) {
    start = clock_start();
    if (party == ALICE) {
      uint64_t *mac = new uint64_t[test_n];
      svole->triple_gen_send(mac, test_n);
      check_triple(io, Delta, mac, test_n);
      delete[] mac;
    } else {
      __uint128_t *mac = new __uint128_t[test_n];
      svole->triple_gen_recv(mac, test_n);
      std::cout << "base svole: " << time_from(start) * 1000 / test_n
                << " ns per entry" << std::endl;
      check_triple(io, mac, test_n);
      delete[] mac;
    }
  }
  std::cout << "pass check" << std::endl;

}

int main(int argc, char **argv) {
  parse_party_and_port(argv, &party, &port);
  NetIO *io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

  std::cout << std::endl
            << "------------ BASE SVOLE ------------" << std::endl
            << std::endl;
  ;

  test_base_svole(io, party);

  delete io;
  return 0;
}
