#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include <iostream>
using namespace emp;
using namespace std;

int party;

void test_circuit_zk(BoolIO *io, int party,
                     int input_sz_lg) {

  long long test_n = 1 << input_sz_lg;
  auto start = clock_start();
  setup_zk_arith(io, party);
  auto timesetup = time_from(start);
  cout << "time for setup: " << timesetup * 1000 << " " << party << " " << endl;

  //	io->sync();
  start = clock_start();
  __uint128_t ar = 2, br = 3, cr = 4;
  IntFp a((uint64_t)ar, ALICE);
  IntFp b((uint64_t)br, ALICE);
  IntFp c((uint64_t)cr, PUBLIC);
  cout << "time for input in total: " << time_from(start) * 1000 << " " << party
       << " " << endl;

  for (int i = 0; i < test_n; ++i) {
    br = (br + ar) % pr;
    ar = (br * ar) % pr;
  }
  cr = (ar * br) % pr;
  cr = (cr + ar) % pr;

  start = clock_start();
  for (int i = 0; i < test_n; ++i) {
    b = b + a;
    a = b * a;
  }
  c = a * b;
  c = c + a;

  bool ret = c.reveal(cr);
  auto timeuse = time_from(start);
  cout << test_n << "\t" << (timeuse + timesetup) << "\t" << party << " " << ret
       << endl;
  std::cout << std::endl;

  finalize_zk_arith();
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
    std::cout << "usage: [binary] PARTY LOG(NUM_GATES)" << std::endl;
    return -1;
  } else if (argc == 2) {
    num = 16;
  } else {
    num = atoi(argv[2]);
  }

  test_circuit_zk(&io, party, num);

  return 0;
}
