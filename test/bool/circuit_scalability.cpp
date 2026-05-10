#include "../test_io_helpers.h"
#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include <iostream>
using namespace emp;
using namespace std;

int port, party;
const int threads = 1;

void test_circuit_zk(BoolIO *ios[threads], int party, int input_sz_lg) {

  long long input_sz = 1 << input_sz_lg;
  setup_zk_bool(ios[0], party);
  auto start = clock_start();
  Integer a(32, 2, ALICE);
  Integer b(32, 3, ALICE);
  Integer c(32, 0, PUBLIC);
  for (int i = 0; i < input_sz; ++i) {
    b = b + a;
    for (int j = 0; j < 32; ++j) {
      a[j] = a[j] & b[j];
      a[(j + 3) % 32] = a[(j + 2) % 32] | b[j];
    }
    for (int j = 0; j < 5; ++j)
      b[j + 2] = a[j + 4] & b[j + 10];
    c = a ^ b;
  }
  Bit ret = Bit(false, PUBLIC);
  bool ret_b = ret.reveal<bool>(PUBLIC);
  finalize_zk_bool();
  cout << 100 * input_sz << "\t" << time_from(start) << " " << party << endl;
  cout << ret_b << std::endl;
}

int main(int argc, char **argv) {
  parse_party_and_port(argv, &party, &port);
  BoolIO *ios[threads];
  make_bool_ios(ios, party, port);

  std::cout << std::endl
            << "------------ circuit zero-knowledge proof test ------------"
            << std::endl
            << std::endl;
  ;

  int num = 0;
  if (argc < 3) {
    std::cout
        << "usage: bin/bool/circuit_scalability_bool PARTY PORT LOG(NUM_GATES)"
        << std::endl;
    return -1;
  } else if (argc == 3) {
    num = 15;
  } else {
    num = atoi(argv[3]);
  }

  test_circuit_zk(ios, party, num);

  destroy_bool_ios(ios);
  return 0;
}
