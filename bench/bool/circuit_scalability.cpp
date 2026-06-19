#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include <iostream>
using namespace emp;
using namespace std;

int party;
using Int32 = Int_T<ZKBoolSession::ctx_t, 32>;   // signed, fixed width: a WireValue

void test_circuit_zk(BoolIO *io, int party, int input_sz_lg) {

  long long input_sz = 1 << input_sz_lg;
  // ~100 AND gates per iteration ⇒ ~100*input_sz COTs; size the SilentFerret
  // prepay to that so all COT traffic + malicious checks ship once at setup and
  // the whole proof's COT draws are wire-free (minimal round-trips).
  ZKBoolSession sess(io, party, 100LL * input_sz);
  auto start = clock_start();
  Int32 a = sess.input<Int32>(ALICE, 2);
  Int32 b = sess.input<Int32>(ALICE, 3);
  Int32 c = sess.input<Int32>(PUBLIC, 0);
  // Int_T::operator[] returns a Bit by value (not a writable ref like the old
  // SignedInt), so mutate individual bits through the public wire storage .w[].
  for (int i = 0; i < input_sz; ++i) {
    b = b + a;
    for (int j = 0; j < 32; ++j) {
      a.w[j] = (a[j] & b[j]).w;
      a.w[(j + 3) % 32] = (a[(j + 2) % 32] | b[j]).w;
    }
    for (int j = 0; j < 5; ++j)
      b.w[j + 2] = (a[j + 4] & b[j + 10]).w;
    c = a ^ b;
  }
  ZKBit ret = ZKBit::constant(sess.ctx(), false);
  bool ret_b = sess.reveal(ret, PUBLIC).value_or(false);
  sess.finalize();
  cout << 100 * input_sz << "\t" << time_from(start) << " " << party << endl;
  cout << ret_b << std::endl;
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
        << "usage: bin/bool/circuit_scalability_bool PARTY LOG(NUM_GATES)"
        << std::endl;
    return -1;
  } else if (argc == 2) {
    num = 12;
  } else {
    num = atoi(argv[2]);
  }

  test_circuit_zk(&io, party, num);

  return 0;
}
