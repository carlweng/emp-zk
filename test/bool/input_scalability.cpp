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
    setup_zk_bool(ios, threads, party);
    Integer *a = new Integer[input_sz / 32];
    for (int i = 0; i < input_sz / 32; ++i)
      a[i] = Integer(32, i, ALICE);

    a[0][0].reveal<bool>(PUBLIC);
    finalize_zk_bool();
    double timeused = time_from(start);
    cout << input_sz << "\t" << timeused << endl;
    delete[] a;
  } else {
    long long unit = 1 << 24;
    auto start = clock_start();
    setup_zk_bool(ios, threads, party);
    int round = input_sz / unit;
    Integer **a = (Integer **)malloc(round * sizeof(Bit *));
    for (int i = 0; i < round; ++i) {
      a[i] = new Integer[unit];
      for (int j = 0; j < unit / 32; ++j)
        a[i][j] = Integer(32, j, ALICE);
    }
    a[0][0][0].reveal<bool>(PUBLIC);
    bool cheated = finalize_zk_bool();
    if (cheated)
      error("cheated\n");
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
    num = 20;
  } else {
    num = atoi(argv[3]);
  }

  test_circuit_zk(ios, party, num);

  destroy_bool_ios(ios);
  return 0;
}
