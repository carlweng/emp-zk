#include "../test_io_helpers.h"
#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include <iostream>
using namespace emp;
using namespace std;

int port, party;
const int threads = 1;

void test_circuit_zk(BoolIO *ios[threads], int party, int log_trial) {

  long long input_sz = 1 << log_trial;
  if (input_sz < 100000000LL) {
    auto start = clock_start();
    ZKBoolSession sess(ios[0], party);
    ZKInt *a = new ZKInt[input_sz / 32];
    for (int i = 0; i < input_sz / 32; ++i)
      a[i] = sess.input_int(32, i, ALICE);

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
    ZKInt **a = (ZKInt **)malloc(round * sizeof(ZKInt *));
    for (int i = 0; i < round; ++i) {
      a[i] = new ZKInt[unit];
      for (int j = 0; j < unit / 32; ++j)
        a[i][j] = sess.input_int(32, j, ALICE);
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
