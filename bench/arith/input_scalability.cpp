#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include <iostream>
using namespace emp;
using namespace std;

int party;

void test_input_speed(BoolIO *io, int party, int input_sz_log) {
  long long sz = input_sz_log;
  std::cout << "input size: " << sz << std::endl;
  srand(time(NULL));
  uint64_t *a = new uint64_t[sz];
  for (int i = 0; i < sz; ++i)
    a[i] = rand() % PR;

  setup_zk_arith(io, party);

  IntFp *x = new IntFp[sz];

  /* normal input */
  auto start = clock_start();
  for (int i = 0; i < sz; ++i)
    x[i] = IntFp(a[i], ALICE);
  double tt = time_from(start);
  std::cout << "normal input average time: " << tt * 1000 / sz
            << " ns per element" << std::endl;

  /* batch input */
  start = clock_start();
  batch_feed(x, a, sz);
  tt = time_from(start);
  std::cout << "batch input average time: " << tt * 1000 / sz
            << " ns per element" << std::endl;

  finalize_zk_arith();

  delete[] a;
  delete[] x;
}

int main(int argc, char **argv) {
  party = parse_party(argv);
  auto netio = (party == ALICE) ? NetIO::listen(peer_port()) : NetIO::connect(peer_ip(), peer_port());
  BoolIO io(netio.get(), party == ALICE);

  std::cout << std::endl
            << "------------ circuit zero-knowledge proof test ------------"
            << std::endl
            << std::endl;
  ;

  int num = 0;
  if (argc < 2) {
    std::cout << "usage: [binary] PARTY LOG(INPUT_SZ)" << std::endl;
    return -1;
  } else if (argc == 2) {
    num = 20;
  } else {
    num = atoi(argv[2]);
  }

  test_input_speed(&io, party, num);

  return 0;
}
