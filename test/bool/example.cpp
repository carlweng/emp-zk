#include "../test_io_helpers.h"
#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include <iostream>
using namespace emp;
using namespace std;

int port, party;
const int threads = 1;

void test_circuit_zk(BoolIO *ios[threads], int party) {
  ZKBoolSession sess(ios[0], party);
  ZKInt a = sess.input_int(32, 3, ALICE);
  ZKInt b = sess.input_int(32, 2, ALICE);
  cout << sess.reveal_int(a - b, PUBLIC).value_or(0) << endl;

  sess.finalize();
}

int main(int argc, char **argv) {
  parse_party_and_port(argv, &party, &port);
  BoolIO *ios[threads];
  make_bool_ios(ios, party, port);

  test_circuit_zk(ios, party);

  destroy_bool_ios(ios);
  return 0;
}
