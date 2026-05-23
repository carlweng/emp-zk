#include "../test_io_helpers.h"
#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk.h"
#include <iostream>
using namespace emp;
using namespace std;

int port, party;
const int threads = 1;
int index_sz = 5, val_sz = 32;

void test(BoolIO *ios[threads], int party, bool bad) {
  setup_zk_bool(ios[0], party);
  int test_n = (1 << index_sz);   // number of cells

  // Memory content x[i] = 2*i.
  vector<Integer> data;
  for (int i = 0; i < test_n; ++i)
    data.push_back(Integer(val_sz, 2 * i, ALICE));

  int rounds = 8;
  int64_t T = (int64_t)rounds * test_n;   // number of lookups

  ZKROM *rom = new ZKROM(party, index_sz, val_sz, T);
  rom->init(data);

  // Soundness check: a malicious prover forges cell 0's value. The reads of
  // cell 0 then carry the wrong value and won't match any write → check()
  // must abort on the verifier.
  if (bad && party == ALICE) rom->mem[0] ^= 1;

  auto start = clock_start();
  // Read every cell several times.
  int wrong = 0;
  for (int r = 0; r < rounds; ++r)
    for (int i = 0; i < test_n; ++i) {
      Integer res = rom->read(Integer(index_sz, i, PUBLIC));
      Bit eq = res == Integer(val_sz, i * 2, ALICE);
      if (!eq.reveal<bool>(PUBLIC)) wrong++;
    }
  rom->check();   // proves reads ∼ writes; aborts on a forged read
  double t = time_from(start);

  finalize_zk_bool();
  int accesses = rounds * test_n;
  cout << "ROM ok (cells=" << test_n << ", accesses=" << accesses
       << ", wrong=" << wrong << ")  " << t / accesses << " us/access  party "
       << party << endl;
}

int main(int argc, char **argv) {
  parse_party_and_port(argv, &party, &port);
  BoolIO *ios[threads];
  make_bool_ios(ios, party, port);

  bool bad = (argc >= 4 && string(argv[3]) == "bad");
  test(ios, party, bad);

  destroy_bool_ios(ios);
  return 0;
}
