#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk.h"
#include <iostream>
using namespace emp;
using namespace std;

int port, party;
const int threads = 1;
int index_sz = 3, step_sz = 18, val_sz = 128;

void test(BoolIO *ios[threads], int party) {
  setup_zk_bool(ios[0], party);
  ZKRamExt<BoolIO> *ram =
      new ZKRamExt<BoolIO>(party, index_sz, step_sz, val_sz);

  uint64_t block_sz = (val_sz + 63) / 64;
  vector<Integer> val(block_sz);
  for (int i = 0; i < (1 << index_sz); ++i) {
    for (int j = 0; j < block_sz; ++j) {
      val[j] = Integer(64, 2 * i + j, ALICE);
    }
    ram->write(val, Integer(index_sz, i, PUBLIC));
    ram->refresh();
  }
  for (int i = 0; i < (1 << index_sz); ++i) {
    vector<Integer> res;
    ram->read(res, Integer(index_sz, i, PUBLIC));
    ram->refresh();
    for (int j = 0; j < block_sz; ++j) {
      Bit eq = res[j].equal(Integer(64, i * 2 + j, ALICE));
      if (eq.reveal(PUBLIC) != true) {
        cout << i << "something is wrong!!\n";
      }
    }
  }
  ram->check();
  /*for(int i = 0; i < (1<<index_sz); ++i) {
          ram->write(Integer(index_sz, i, PUBLIC), Integer(val_sz, 3*i,
  PUBLIC)); ram->refresh();
  }
  for(int i = 0; i < (1<<index_sz); ++i) {
          Integer res = ram->read(Integer(index_sz, i, PUBLIC));
          ram->refresh();
          Bit eq = res == Integer(val_sz, i*3, ALICE);
          if(!eq.reveal<bool>(PUBLIC)) {
                  cout <<i<<"something is wrong!!\n";
          }
  }
  ram->check();*/
  delete ram;
  finalize_zk_bool();
  cout << "done\n";
}

int main(int argc, char **argv) {
  parse_party_and_port(argv, &party, &port);
  BoolIO *ios[threads];
  for (int i = 0; i < threads; ++i)
    ios[i] = new BoolIO(
        new NetIO(party == ALICE ? nullptr : "127.0.0.1", port),
        party == ALICE);

  if (argc > 3)
    index_sz = atoi(argv[3]);

  test(ios, party);
  // bench(ios, party);

  for (int i = 0; i < threads; ++i) {
    NetIO *raw = static_cast<NetIO *>(ios[i]->io);
    delete ios[i];
    delete raw;
  }
  return 0;
}
