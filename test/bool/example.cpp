#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include <iostream>
using namespace emp;
using namespace std;

int party;

using Int32 = Int_T<ZKBoolSession::ctx_t, 32>;   // signed, fixed width: a WireValue

void test_circuit_zk(BoolIO *io, int party) {
  ZKBoolSession sess(io, party);
  Int32 a = sess.input<Int32>(ALICE, 3);
  Int32 b = sess.input<Int32>(ALICE, 2);
  cout << sess.reveal(a - b, PUBLIC).value_or(0) << endl;

  sess.finalize();
}

int main(int argc, char **argv) {
  party = parse_party(argv);
  auto netio = (party == ALICE) ? NetIO::listen(peer_port()) : NetIO::connect(peer_ip(), peer_port());
  BoolIO io(netio.get(), party == ALICE);

  test_circuit_zk(&io, party);

  return 0;
}
