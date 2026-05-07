#include "../test_io_helpers.h"
#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include <iostream>
using namespace emp;
using namespace std;

int port, party;
int repeat, sz;
const int threads = 1;

using namespace std;

void test_lowmc(BoolIO *ios[threads], int party) {
  unsigned nblocks = 10;
  unsigned test_sz = nblocks * blocksize;
  setup_zk_bool(ios, threads, party);
  sync_zk_bool();

  bool *key_b = new bool[keysize];
  bool *ptx_b = new bool[test_sz];
  bool *ctx_b = new bool[test_sz];
  bool *ctx_rev = new bool[test_sz];
  Bit *ptx = new Bit[test_sz];
  Bit *ctx = new Bit[test_sz];

  PRG prg;
  prg.reseed(&all_one_block);
  prg.random_bool(key_b, keysize);
  // cout<<"key:";for(int i = 0; i < keysize; ++i)cout<<key_b[i];cout<<endl;
  prg.random_bool(ptx_b, test_sz);
  // cout<<"ptx:";for(int i = 0; i < test_sz; ++i)cout<<ptx_b[i];cout<<endl;
  backend->feed((block *)ptx, ALICE, ptx_b, test_sz);

  ZKLowMC *lowmc = new ZKLowMC(key_b);

  lowmc->encrypt(ctx_b, ptx_b, nblocks);
  // cout<<"ctx loc:";for(int i = 0; i < test_sz; ++i)cout<<ctx_b[i];cout<<endl;

  auto start = clock_start();
  lowmc->encrypt(ctx, ptx, nblocks);
  double tt = time_from(start);

  backend->reveal(ctx_rev, PUBLIC, (block *)ctx, test_sz);

  bool cheated = finalize_zk_bool();
  if (cheated)
    error("cheated\n");

  // cout<<"ctx rev:";for(int i = 0; i < test_sz;
  // ++i)cout<<ctx_rev[i];cout<<endl;
  std::cout << "check encryption consistency" << std::endl;
  std::cout << memcmp(ctx_b, ctx_rev, test_sz * sizeof(bool)) << std::endl;

  std::cout << "time: " << tt / nblocks << std::endl;

  delete[] key_b;
  delete[] ptx_b;
  delete[] ctx_b;
  delete[] ctx_rev;
  delete[] ptx;
  delete[] ctx;
}

int main(int argc, char **argv) {
  parse_party_and_port(argv, &party, &port);
  BoolIO *ios[threads];
  make_bool_ios(ios, party, port);

  std::cout << std::endl << "------------ ";
  std::cout << "LowMC block cipher test";
  std::cout << " ------------" << std::endl << std::endl;
  ;

  test_lowmc(ios, party);

  destroy_bool_ios(ios);
  return 0;
}
