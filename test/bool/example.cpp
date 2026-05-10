#include "../test_io_helpers.h"
#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include <iostream>
using namespace emp;
using namespace std;

int port, party;
const int threads = 1;

void test_circuit_zk(BoolIO *ios[threads], int party) {
  setup_zk_bool(ios, threads, party);
  Integer a(32, 3, ALICE);
  Integer b(32, 2, ALICE);
  cout << (a - b).reveal<uint32_t>(PUBLIC) << endl;

  finalize_zk_bool();
}

int main(int argc, char **argv) {
  parse_party_and_port(argv, &party, &port);
  BoolIO *ios[threads];
  make_bool_ios(ios, party, port);

  test_circuit_zk(ios, party);

  destroy_bool_ios(ios);
  return 0;
}
