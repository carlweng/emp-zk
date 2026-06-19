#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include <iostream>
using namespace emp;
using namespace std;

int party;
const int W = 64;   // bit width of each fed value

// Build a valid authenticated f2k wire from a fresh ALICE-input value:
// feed W authenticated bits, then pack them into one F(2^128) element via
// the local Σ·Xⁱ map (mac from the bit wires, val from the cleartext LSBs).
static F2kAuthValue make_wire(ZKBoolSession &sess, uint64_t v) {
  ZKInt x = sess.input<ZKInt>(ALICE, v, W);
  vector<F2kAuthValue> out;
  ramzk_pack_record(&sess.engine(), {&x}, out);
  return out[0];
}

void test_f2k_mul(BoolIO *io, int party, int lg) {
  long long n = 1LL << lg;
  ZKBoolSession sess(io, party);
  auto *bb = &sess.engine();

  F2kAuthValue a = make_wire(sess, 2), b = make_wire(sess, 3);

  // Warm up: the first f2k op lazily bootstraps the f2k VOLE; keep that
  // one-time cost out of the timed loop.
  F2kAuthValue w = a;
  bb->f2k_mul(w, w, b);

  auto start = clock_start();
  for (long long i = 0; i < n; ++i)
    bb->f2k_mul(a, a, b);
  double t = time_from(start);

  // finalize runs the f2k batch multiplication check — an abort here would
  // mean the chain was computed wrong.
  sess.finalize();

  cout << n << " f2k_mul\t" << t << " us\t"
       << (double)n / (t / 1e6) / 1e6 << " M mult/s\tparty " << party << endl;
}

int main(int argc, char **argv) {
  party = parse_party(argv);
  auto netio = (party == ALICE) ? NetIO::listen(peer_port()) : NetIO::connect(peer_ip(), peer_port());
  BoolIO io(netio.get(), party == ALICE);

  int lg = (argc >= 3) ? atoi(argv[2]) : 22;
  test_f2k_mul(&io, party, lg);

  return 0;
}
