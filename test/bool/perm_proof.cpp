#include "../test_io_helpers.h"
#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include <iostream>
#include <string>
using namespace emp;
using namespace std;

int port, party;
const int threads = 1;
const int W = 64;   // bit width of each fed value

// Build a valid authenticated f2k wire from a fresh ALICE-input value: feed W
// authenticated bits and pack them into one F(2^128) element via the local
// Σ·Xⁱ map (mac from the bit wires, val from the cleartext LSBs).
static F2kAuthValue make_wire(uint64_t v) {
  SignedInt x(W, v, ALICE);
  vector<F2kAuthValue> out;
  ramzk_pack_record(get_bool_backend(), {&x}, out);
  return out[0];
}

// n elements, each `m` wires (payload = m*128 bits). A is the natural order;
// B is the same elements in reversed order (a permutation). `bad` corrupts
// one wire of B so the multiset no longer matches.
void test_perm(BoolIO *ios[threads], int party, int n, int bits,
               const string &mode) {
  setup_zk_bool(ios[0], party);
  const int m = (bits + 127) / 128;
  const bool bad = (mode == "bad");
  // "periodic" exercises explicit per-batch compress(): each fold draws its
  // own coefficient, so matched elements must stay in the same batch — use
  // identity order. Otherwise B is the reversed permutation, folded once.
  const bool periodic = (mode == "periodic");

  vector<F2kAuthValue> elems((size_t)n * m);
  for (int i = 0; i < n; ++i)
    for (int j = 0; j < m; ++j)
      elems[(size_t)i * m + j] =
          make_wire(((uint64_t)i * 2654435761ull + 7) ^ ((uint64_t)j << 40));

  auto start = clock_start();
  ZKPermProof perm(bits);
  const int chunk = (n >= 4) ? n / 4 : n;
  for (int i = 0; i < n; ++i) {
    perm.add_A(&elems[(size_t)i * m]);
    int src = periodic ? i : (n - 1 - i);
    if (bad && i == 0) {
      F2kAuthValue e[8];                  // corrupt one element's first wire
      for (int j = 0; j < m; ++j) e[j] = elems[(size_t)src * m + j];
      e[0] = make_wire(0xDEADBEEFull);
      perm.add_B(e);
    } else {
      perm.add_B(&elems[(size_t)src * m]);
    }
    if (periodic && (i + 1) % chunk == 0) perm.compress();   // fold this batch
  }
  perm.check_eq();   // passes iff B is a permutation of A
  double t = time_from(start);

  finalize_zk_bool();
  cout << "perm check (n=" << n << ", bits=" << bits << " [" << m << " blk]"
       << (mode.empty() ? "" : ", " + mode) << ") PASSED\t" << t
       << " us\tparty " << party << endl;
}

int main(int argc, char **argv) {
  parse_party_and_port(argv, &party, &port);
  BoolIO *ios[threads];
  make_bool_ios(ios, party, port);

  int n = (argc >= 4) ? atoi(argv[3]) : 100000;
  int bits = (argc >= 5) ? atoi(argv[4]) : 128;
  string mode = (argc >= 6) ? string(argv[5]) : "";   // "", "periodic", "bad"
  test_perm(ios, party, n, bits, mode);

  destroy_bool_ios(ios);
  return 0;
}
