#include "../test_io_helpers.h"
#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include <iostream>
using namespace emp;
using namespace std;

int port, party;
const int threads = 1;

using Int32 = Int_T<ZKBoolContext, 32>;   // signed, fixed width: a WireValue

void test_circuit_zk(BoolIO *ios[threads], int party) {
  ZKBoolSession sess(ios[0], party);
  Int32 a = sess.input<Int32>(ALICE, 3);
  Int32 b = sess.input<Int32>(ALICE, 2);
  cout << sess.reveal(a - b, PUBLIC).value_or(0) << endl;

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
