#include "emp-zk/emp-zk-arith/ostriple.h"
#include "emp-zk/emp-zk-bool/emp-zk-bool.h"
#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include <iostream>
using namespace emp;
using namespace std;

int party;

void test_auth_bit_input(FpOSTriple *os) {
  PRG prg;
  int len = 1024;
  __uint128_t *auth = new __uint128_t[len];
  if (party == ALICE) {
    __uint128_t *in = new __uint128_t[len];
    PRG prg;
    prg.random_block((block *)in, len);
    for (int i = 0; i < len; ++i) {
      in[i] = in[i] & (__uint128_t)0xFFFFFFFFFFFFFFFFLL;
      in[i] = mod(in[i], pr);
      auth[i] = os->authenticated_val_input(in[i]);
    }
    os->check_auth_mac(auth, len);
    delete[] in;
  } else {
    for (int i = 0; i < len; ++i)
      auth[i] = os->authenticated_val_input();
    os->check_auth_mac(auth, len);
  }
  delete[] auth;
}

void test_compute_and_gate_check(FpOSTriple *os) {
  PRG prg;
  int len = 1024;
  auto start = clock_start();
  __uint128_t *a = new __uint128_t[len];
  __uint128_t *b = new __uint128_t[len];
  __uint128_t *c = new __uint128_t[len];
  if (party == ALICE) {
    __uint128_t *ain = new __uint128_t[len];
    __uint128_t *bin = new __uint128_t[len];
    PRG prg;
    prg.random_block((block *)ain, len);
    prg.random_block((block *)bin, len);
    for (int i = 0; i < len; ++i) {
      ain[i] = ain[i] & (__uint128_t)0xFFFFFFFFFFFFFFFFLL;
      ain[i] = mod(ain[i], pr);
      a[i] = os->authenticated_val_input(ain[i]);
      bin[i] = bin[i] & (__uint128_t)0xFFFFFFFFFFFFFFFFLL;
      bin[i] = mod(bin[i], pr);
      b[i] = os->authenticated_val_input(bin[i]);
      c[i] = os->auth_compute_mul_send(a[i], b[i]);
    }
    delete[] ain;
    delete[] bin;
    std::cout << "sender time: " << time_from(start) << std::endl;
    os->check_compute_mul(a, b, c, len);
  } else {
    for (int i = 0; i < len; ++i) {
      a[i] = os->authenticated_val_input();
      b[i] = os->authenticated_val_input();
      c[i] = os->auth_compute_mul_recv(a[i], b[i]);
    }
    std::cout << "recver time: " << time_from(start) << std::endl;
    os->check_compute_mul(a, b, c, len);
  }

  /*std::cout << "number of triples computed in buffer: " << os->andgate_cnt <<
  std::endl; os->andgate_correctness_check(); std::cout << "check for
  cut-and-choose and check\n";*/

  delete[] a;
  delete[] b;
  delete[] c;
}

// Vectorized multiply: build `len` independent input pairs, run the batched
// auth_compute_mul (one call, batched send, threaded compute), verify triples.
void test_vectorized_mul(FpOSTriple *os, int64_t len) {
  __uint128_t *a = new __uint128_t[len];
  __uint128_t *b = new __uint128_t[len];
  __uint128_t *c = new __uint128_t[len];
  if (party == ALICE) {
    __uint128_t *ain = new __uint128_t[len];
    __uint128_t *bin = new __uint128_t[len];
    PRG prg;
    prg.random_block((block *)ain, len);
    prg.random_block((block *)bin, len);
    for (int64_t i = 0; i < len; ++i) {
      ain[i] = mod(ain[i] & (__uint128_t)0xFFFFFFFFFFFFFFFFLL, pr);
      a[i] = os->authenticated_val_input(ain[i]);
      bin[i] = mod(bin[i] & (__uint128_t)0xFFFFFFFFFFFFFFFFLL, pr);
      b[i] = os->authenticated_val_input(bin[i]);
    }
    auto start = clock_start();                         // time the mul only
    os->auth_compute_mul_send(c, a, b, len);            // batched + threaded
    std::cout << "vectorized mul sender time: " << time_from(start) << std::endl;
    os->check_compute_mul(a, b, c, len);
    delete[] ain;
    delete[] bin;
  } else {
    for (int64_t i = 0; i < len; ++i) {
      a[i] = os->authenticated_val_input();
      b[i] = os->authenticated_val_input();
    }
    auto start = clock_start();                         // time the mul only
    os->auth_compute_mul_recv(c, a, b, len);            // batched + threaded
    std::cout << "vectorized mul recver time: " << time_from(start) << std::endl;
    os->check_compute_mul(a, b, c, len);
  }
  delete[] a;
  delete[] b;
  delete[] c;
}

void test_ostriple(BoolIO *io, int party, int threads) {
  auto t1 = clock_start();
  FpOSTriple os(party, io, threads);
  cout << party << "\tconstructor\t" << time_from(t1) << " us" << endl;

  test_auth_bit_input(&os);
  std::cout << "check for authenticated bit input\n";

  test_compute_and_gate_check(&os);
  std::cout << "check for multiplication (scalar)\n";

  test_vectorized_mul(&os, 1 << 20);
  std::cout << "check for multiplication (vectorized, threads=" << threads
            << ")\n";

  std::cout << std::endl;
}

int main(int argc, char **argv) {
  party = parse_party(argv);
  auto netio = (party == ALICE) ? NetIO::listen(peer_port()) : NetIO::connect(peer_ip(), peer_port());
  BoolIO io(netio.get(), party == ALICE);

  std::cout << std::endl
            << "------------ triple generation test ------------" << std::endl
            << std::endl;
  ;

  int threads = (argc > 3) ? std::max(1, atoi(argv[3])) : 1;
  test_ostriple(&io, party, threads);

  return 0;
}
