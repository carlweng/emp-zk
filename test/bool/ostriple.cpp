#include "../test_io_helpers.h"
#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include <iostream>
using namespace emp;
using namespace std;

int port, party;
const int threads = 1;

// Debug helpers — formerly OSTriple::check_auth_mac / check_compute_and.
// They live here because they're used by exactly this one test and they
// open a side-channel (a separate IOChannel) to ground-truth the prover's
// claims, so they don't belong in the production header.
static void check_auth_mac(OSTriple *os, block *auth, bool *in, int len,
                           IOChannel *tio) {
  if (os->party == ALICE) {
    tio->send_data(auth, len * sizeof(block));
    tio->send_data(in, len * sizeof(bool));
  } else {
    block *auth_recv = new block[len];
    tio->recv_data(auth_recv, len * sizeof(block));
    tio->recv_data(in, len * sizeof(bool));
    for (int i = 0; i < len; ++i) {
      if (in[i] != getLSB(auth_recv[i]))
        error("check1");
      auth[i] = OSTriple::clear_lsb(auth[i]);
      block mac = os->xor_delta_if(auth[i], in[i]);
      if (!cmpBlock(&mac, &auth_recv[i], 1))
        error("check2");
    }
    delete[] auth_recv;
  }
}

static void check_compute_and(OSTriple *os, block *a, block *b, block *c,
                              int len, IOChannel *tio) {
  if (os->party == ALICE) {
    tio->send_data(a, len * sizeof(block));
    tio->send_data(b, len * sizeof(block));
    tio->send_data(c, len * sizeof(block));
  } else {
    block *recv = new block[3 * len];
    tio->recv_data(recv, len * sizeof(block));
    tio->recv_data(recv + len, len * sizeof(block));
    tio->recv_data(recv + 2 * len, len * sizeof(block));
    for (int i = 0; i < len; ++i) {
      bool ar = getLSB(recv[i]);
      bool br = getLSB(recv[len + i]);
      bool cr = getLSB(recv[2 * len + i]);
      if (cr != (ar & br))
        error("check3");
      block v[3] = {OSTriple::clear_lsb(a[i]), OSTriple::clear_lsb(b[i]),
                    OSTriple::clear_lsb(c[i])};
      v[0] = os->xor_delta_if(v[0], ar);
      v[1] = os->xor_delta_if(v[1], br);
      v[2] = os->xor_delta_if(v[2], cr);
      if (!cmpBlock(v, recv + i, 1))
        error("check4");
      if (!cmpBlock(v + 1, recv + len + i, 1))
        error("check5");
      if (!cmpBlock(v + 2, recv + 2 * len + i, 1))
        error("check6");
    }
    delete[] recv;
  }
}

void test_auth_bit_input(OSTriple *os, BoolIO *io) {
  PRG prg;
  int len = 1024;
  block *auth = new block[len];
  bool *in = new bool[len];
  if (party == ALICE) {
    PRG prg;
    prg.random_bool(in, len);
    os->authenticated_bits_input(auth, in, len);
    check_auth_mac(os, auth, in, len, io);
  } else {
    os->authenticated_bits_input(auth, in, len);
    check_auth_mac(os, auth, in, len, io);
  }
  delete[] auth;
  delete[] in;
  io->flush();
}

void test_compute_and_gate_check(OSTriple *os, BoolIO *io) {
  PRG prg;
  int len = 1024;
  block *a = new block[3 * len];
  bool *ain = new bool[3 * len];
  if (party == ALICE) {
    prg.random_bool(ain, 2 * len);
  }
  os->authenticated_bits_input(a, ain, 2 * len);
  check_auth_mac(os, a, ain, 2 * len, io);
  std::cout << "generate triple inputs" << std::endl;
  for (int i = 0; i < len; ++i) {
    a[2 * len + i] = os->auth_compute_and(a[i], a[len + i]);
    ain[2 * len + i] = getLSB(a[2 * len + i]);
  }
  std::cout << "compute AND" << std::endl;
  check_auth_mac(os, a + 2 * len, ain + 2 * len, len, io);

  check_compute_and(os, a, a + len, a + 2 * len, len, io);
  std::cout << "check for computing AND gate\n";

  delete[] a;
  delete[] ain;
  io->flush();
}
void test_ostriple(BoolIO *ios[threads + 1], int party) {
  auto t1 = clock_start();
  OSTriple os(party, threads, ios);
  cout << party << "\tconstructor\t" << time_from(t1) << " us" << endl;

  test_auth_bit_input(&os, ios[0]);
  std::cout << "check for authenticated bit input\n";

  test_compute_and_gate_check(&os, ios[0]);
}

int main(int argc, char **argv) {
  parse_party_and_port(argv, &party, &port);
  BoolIO *ios[threads];
  make_bool_ios(ios, party, port);

  std::cout << std::endl
            << "------------ triple generation test ------------" << std::endl
            << std::endl;
  ;

  test_ostriple(ios, party);
  destroy_bool_ios(ios);
  return 0;
}
