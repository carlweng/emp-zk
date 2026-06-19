#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include <iostream>
using namespace emp;
using namespace std;

int party;
using Int32 = Int_T<ZKBoolSession::ctx_t, 32>;   // signed, fixed width: a WireValue

void test_circuit_zk(BoolIO *io, int party, int log_trial) {

  long long input_sz = 1 << log_trial;
  if (input_sz < 100000000LL) {
    auto start = clock_start();
    ZKBoolSession sess(io, party);
    Int32 *a = new Int32[input_sz / 32];
    for (int i = 0; i < input_sz / 32; ++i)
      a[i] = sess.input<Int32>(ALICE, i);

    sess.reveal(a[0][0], PUBLIC);
    sess.finalize();
    double timeused = time_from(start);
    cout << input_sz << "\t" << timeused << endl;
    delete[] a;
  } else {
    long long unit = 1 << 24;
    auto start = clock_start();
    ZKBoolSession sess(io, party);
    int round = input_sz / unit;
    Int32 **a = (Int32 **)malloc(round * sizeof(Int32 *));
    for (int i = 0; i < round; ++i) {
      a[i] = new Int32[unit];
      for (int j = 0; j < unit / 32; ++j)
        a[i][j] = sess.input<Int32>(ALICE, j);
    }
    sess.reveal(a[0][0][0], PUBLIC);
    sess.finalize();
    double timeused = time_from(start);
    cout << input_sz << "\t" << timeused << endl;
    for (int i = 0; i < 8; ++i)
      delete[] a[i];
    free(a);
  }
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
    std::cout
        << "usage: bin/bool/input_scalability_bool PARTY LOG(INPUT_SZ)"
        << std::endl;
    return -1;
  } else if (argc == 2) {
    num = 18;
  } else {
    num = atoi(argv[2]);
  }

  test_circuit_zk(&io, party, num);

  return 0;
}
