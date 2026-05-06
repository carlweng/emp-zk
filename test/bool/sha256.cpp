#include <emp-zk/emp-zk.h>
#include <iostream>
using namespace std;
const string circuit_file_location =
    macro_xstr(EMP_CIRCUIT_PATH) + string("bristol_format/");
const int threads = 1;
void get_plain(bool *res, bool *wit, const char *file) {
  setup_clear_backend();
  BristolFormat cf(file);
  vector<Bit> W, P, O;
  W.resize(cf.n1);
  for (int i = 0; i < cf.n1; ++i)
    W[i] = Bit(wit[i], PUBLIC);
  O.resize(cf.n1);
  for (int i = 0; i < cf.n1; ++i)
    O[i] = Bit(false, PUBLIC);
  cf.compute(O.data(), W.data(), P.data());
  for (int i = 0; i < 64; ++i)
    cf.compute(O.data(), O.data(), P.data());
  for (int i = 0; i < cf.n3; ++i) {
    res[i] = O[i].reveal<bool>(PUBLIC);
  }
  finalize_clear_backend();
}
int main(int argc, char **argv) {
  int party, port;
  parse_party_and_port(argv, &party, &port);
  string filename = circuit_file_location + string("sha-256.txt");
  bool *witness = new bool[512];
  memset(witness, false, 512);
  bool *output = new bool[256];
  get_plain(output, witness, filename.c_str());
  BoolIO<NetIO> *ios[threads];
  for (int i = 0; i < threads; ++i)
    ios[i] = new BoolIO<NetIO>(
        new NetIO(party == ALICE ? nullptr : "127.0.0.1", port + i),
        party == ALICE);

  setup_zk_bool<BoolIO<NetIO>>(ios, threads, party);
  vector<Bit> W, O;
  for (int i = 0; i < 512; ++i)
    W.push_back(Bit(witness[i], ALICE));
  O.resize(512);
  for (int i = 0; i < 512; ++i)
    O[i] = Bit(false, PUBLIC);

  BristolFormat cf(filename.c_str());
  cf.compute(O.data(), W.data(), (const Bit *)nullptr);
  for (int i = 0; i < 64; ++i)
    cf.compute(O.data(), O.data(), (const Bit *)nullptr);
  for (int i = 0; i < 256; ++i) {
    bool tmp = O[i].reveal<bool>(PUBLIC);
    if (tmp != output[i])
      error("wrong");
  }

  bool cheated = finalize_zk_bool<BoolIO<NetIO>>();
  if (cheated)
    error("cheated\n");

  for (int i = 0; i < threads; ++i) {
    NetIO *raw = ios[i]->io;
    delete ios[i];
    delete raw;
  }

  return 0;
}
