#include "../test_io_helpers.h"
#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk.h"
#include <iostream>
using namespace emp;
using namespace std;

int port, party;
const int threads = 1;

// ZKSet is the freshness primitive of the read/write RAM: the public range
// {1, …, T}, with prove_member(v) proving v is in range. An in-range stream
// must pass; a single out-of-range query must make the verifier abort
// (Yang–Heath §4.2 / Remark 1).
void test(BoolIO *ios[threads], int party, bool bad) {
  ZKBoolSession sess(ios[0], party);
  int64_t T = 64;
  int elem_sz = (int)ramzk_bits_for(T);

  ZKSet *s = new ZKSet(sess, T, elem_sz);

  // Query each element of {1..T}, several elements repeatedly (chains).
  for (int rep = 0; rep < 3; ++rep)
    for (int64_t e = 1; e <= T; ++e)
      s->prove_member(sess.input_int(elem_sz, (uint64_t)e, ALICE));

  // Soundness: 0 ∉ {1..T}, so this query cannot be chained to a setup write.
  if (bad)
    s->prove_member(sess.input_int(elem_sz, (uint64_t)0, ALICE));

  s->check();
  sess.finalize();
  cout << "ZKSet ok (T=" << T << ")  party " << party << endl;
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
