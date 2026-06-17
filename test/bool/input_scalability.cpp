#include "../test_io_helpers.h"
#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include <iostream>
using namespace emp;
using namespace std;

int port, party;
const int threads = 1;
using Int32 = Int_T<ZKBoolContext, 32>;   // signed, fixed width: a WireValue

void test_circuit_zk(BoolIO *ios[threads], int party, int log_trial) {

  long long input_sz = 1 << log_trial;
  if (input_sz < 100000000LL) {
    auto start = clock_start();
    ZKBoolSession sess(ios[0], party);
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
    ZKBoolSession sess(ios[0], party);
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
        << "usage: bin/bool/input_scalability_bool PARTY PORT LOG(INPUT_SZ)"
        << std::endl;
    return -1;
  } else if (argc == 3) {
    num = 18;
  } else {
    num = atoi(argv[3]);
  }

  test_circuit_zk(ios, party, num);

  destroy_bool_ios(ios);
  return 0;
}
