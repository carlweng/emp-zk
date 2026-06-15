#ifndef EMP_ZK_TEST_IO_HELPERS_H__
#define EMP_ZK_TEST_IO_HELPERS_H__
#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include <cstdlib>

namespace emp {

// Construct an array of N BoolIO*, each wrapping a fresh NetIO bound
// to ports [port, port + N). ALICE listens; BOB connects to the peer at
// $EMP_PEER_IP (default 127.0.0.1, so loopback runs are unchanged) — set
// EMP_PEER_IP=<alice-ip> to run the two parties on separate machines.
template <int N>
inline void make_bool_ios(BoolIO *(&ios)[N], int party, int port) {
  const char *peer_env = std::getenv("EMP_PEER_IP");
  const char *peer = (peer_env && peer_env[0]) ? peer_env : "127.0.0.1";
  for (int i = 0; i < N; ++i)
    ios[i] =
        new BoolIO(new NetIO(party == ALICE ? nullptr : peer, port + i),
                   party == ALICE);
}

// Symmetric teardown. BoolIO::~BoolIO calls io->flush() on the wrapped
// NetIO, so the order matters: capture the raw NetIO* first, destroy
// the wrapper, then the NetIO. Doing it the other way is a UAF.
template <int N>
inline void destroy_bool_ios(BoolIO *(&ios)[N]) {
  for (int i = 0; i < N; ++i) {
    NetIO *raw = static_cast<NetIO *>(ios[i]->io);
    delete ios[i];
    delete raw;
  }
}

} // namespace emp
#endif
