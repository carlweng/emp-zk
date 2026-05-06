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

  bool cheat = finalize_zk_bool();
  if (cheat)
    error("cheat!\n");
}

int main(int argc, char **argv) {
  parse_party_and_port(argv, &party, &port);
  BoolIO *ios[threads];
  for (int i = 0; i < threads; ++i)
    ios[i] = new BoolIO(
        new NetIO(party == ALICE ? nullptr : "127.0.0.1", port + i),
        party == ALICE);

  test_circuit_zk(ios, party);

  for (int i = 0; i < threads; ++i) {
    NetIO *raw = static_cast<NetIO *>(ios[i]->io);
    delete ios[i];
    delete raw;
  }
  return 0;
}
