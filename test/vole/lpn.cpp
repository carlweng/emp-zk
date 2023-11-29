#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-vole/emp-vole.h"

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

void test_lpn(NetIO *io, int party) {
  Base_svole<NetIO> *svole;

  // ALICE generate delta
  PRG prg;
  __uint128_t Delta;
  prg.random_data(&Delta, sizeof(__uint128_t));
  Delta = Delta & ((__uint128_t)0xFFFFFFFFFFFFFFFFLL);
  Delta = mod(Delta, pr);

  // test cases reduced for github action
  int test_n = 1016832 / 2;
  int test_k = 158000 / 10;

  ThreadPool pool(1);
  LpnFp<10> lpn(test_n, test_k, &pool, pool.size());

  if (party == ALICE) {
    uint64_t *mac1 = new uint64_t[test_n];
    uint64_t *mac2 = new uint64_t[test_k];
    svole = new Base_svole<NetIO>(party, io, Delta);
    svole->triple_gen_send(mac1, test_n);
    svole->triple_gen_send(mac2, test_k);
    auto start = clock_start();
    lpn.compute_send(mac1, mac2);
    std::cout << "LPN: " << time_from(start) * 1000.0 / test_n << " ns per entry" << std::endl;
    check_triple(io, Delta, mac1, test_n);
    delete[] mac1;
    delete[] mac2;
  } else {
    __uint128_t *mac1 = new __uint128_t[test_n];
    __uint128_t *mac2 = new __uint128_t[test_k];
    svole = new Base_svole<NetIO>(party, io);
    svole->triple_gen_recv(mac1, test_n);
    svole->triple_gen_recv(mac2, test_k);
    auto start = clock_start();
    lpn.compute_recv(mac1, mac2);
    std::cout << "LPN: " << time_from(start) * 1000.0 / test_n << " ns per entry" << std::endl;
    check_triple(io, mac1, test_n);
    delete[] mac1;
    delete[] mac2;
  }

}

int main(int argc, char **argv) {
  parse_party_and_port(argv, &party, &port);
  NetIO *io = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port);

  std::cout << std::endl
            << "------------ LPN ------------" << std::endl
            << std::endl;
  ;

  test_lpn(io, party);

  delete io;
  return 0;
}
