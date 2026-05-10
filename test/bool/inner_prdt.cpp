#include "../test_io_helpers.h"
#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include <iostream>
using namespace emp;
using namespace std;

int port, party;
int repeat, sz;
const int threads = 1;

void test_inner_product(BoolIO *ios[threads], int party) {
  srand(time(NULL));
  bool constant;
  bool *witness = new bool[2 * sz];
  memset(witness, 0, 2 * sz * sizeof(bool));

  setup_zk_bool(ios, threads, party);
  sync_zk_bool();

  Bit *x = new Bit[2 * sz];

  if (party == ALICE) {
    bool sum = 0, tmp;
    PRG prg;
    prg.random_bool(witness, 2 * sz);
    for (int i = 0; i < sz; ++i) {
      tmp = witness[i] & witness[sz + i];
      sum = sum ^ tmp;
    }
    constant = sum;
    ios[0]->send_data(&constant, sizeof(bool));
  } else {
    ios[0]->recv_data(&constant, sizeof(bool));
  }
  ios[0]->flush();

  for (int i = 0; i < 2 * sz; ++i)
    x[i] = Bit(witness[i], ALICE);

  sync_zk_bool();
  auto start = clock_start();
  for (int j = 0; j < repeat; ++j) {
    zkp_inner_prdt(x, x + sz, constant, sz);
  }

  finalize_zk_bool();

  double tt = time_from(start);
  cout << "prove " << repeat << " degree-2 inner_product of length " << sz
       << endl;
  cout << "time use: " << tt / 1000 << " ms" << endl;
  cout << "average time use: " << tt / 1000 / repeat << " ms" << endl;

  delete[] witness;
  delete[] x;
}

int main(int argc, char **argv) {
  parse_party_and_port(argv, &party, &port);
  BoolIO *ios[threads];
  make_bool_ios(ios, party, port);

  std::cout << std::endl << "------------ ";
  std::cout << "ZKP inner_product test";
  std::cout << " ------------" << std::endl << std::endl;
  ;

  if (argc < 3) {
    std::cout << "usage: [binary] PARTY PORT POLY_NUM POLY_DIMENSION"
              << std::endl;
    return -1;
  } else if (argc < 5) {
    repeat = 100;
    sz = 10;
  } else {
    repeat = atoi(argv[3]);
    sz = atoi(argv[4]);
  }

  test_inner_product(ios, party);

  destroy_bool_ios(ios);
  return 0;
}
