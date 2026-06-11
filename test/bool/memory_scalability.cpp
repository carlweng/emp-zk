// ZK memory / throughput scalability: replay the sha256_256 builtin K times over
// the ZK boolean context, reusing one ProgramWorkspace, and report time + peak
// RSS. The point is that peak memory stays bounded as the proven circuit grows —
// replay streams gates through the session rather than materializing the whole
// circuit. C++20.

#include "../test_io_helpers.h"
#include "emp-tool/emp-tool.h"
#include "emp-tool/ir/context/clear.h"
#include "emp-tool/ir/builtins.h"
#include "emp-tool/ir/execute.h"
#include <emp-zk/emp-zk.h>
#include <cstdio>
#include <memory>
#include <span>
#include <vector>
#if defined(__linux__) || defined(__APPLE__)
#include <sys/resource.h>
#endif

using namespace emp;

int port, party;
const int threads = 1;

static long peak_rss_kib() {
#if defined(__linux__) || defined(__APPLE__)
  struct rusage ru;
  getrusage(RUSAGE_SELF, &ru);
#if defined(__APPLE__)
  return ru.ru_maxrss / 1024;   // macOS reports bytes
#else
  return ru.ru_maxrss;          // Linux reports KiB
#endif
#else
  return 0;
#endif
}

int main(int argc, char **argv) {
  parse_party_and_port(argv, &party, &port);
  int K = (argc >= 4) ? atoi(argv[3]) : 8;   // number of replays

  BoolIO *ios[threads];
  make_bool_ios(ios, party, port);

  ZKBoolSession sess(ios[0], party);
  ZKBoolContext &ctx = sess.direct_ctx();
  const circuit::BooleanProgram &prog = circuit::builtin_circuit("sha256_256");
  const int nin = (int)prog.num_inputs;

  std::vector<uint8_t> wit((size_t)nin);
  for (int i = 0; i < nin; ++i)
    wit[(size_t)i] = (uint8_t)(((uint32_t)i * 0x85ebca6bu) >> 13) & 1u;

  ClearCtx cctx;
  auto cout = execute_program(cctx, prog,
                              std::span<const uint8_t>(wit.data(), (size_t)nin));

  auto inbits = std::make_unique<bool[]>((size_t)nin);
  for (int i = 0; i < nin; ++i) inbits[(size_t)i] = wit[(size_t)i] != 0;

  ProgramWorkspace<ZKWire> ws;   // reused across replays -> bounded memory
  auto start = clock_start();
  int wrong = 0;
  for (int k = 0; k < K; ++k) {
    std::vector<ZKWire> zin = sess.input_bits(ALICE, inbits.get(), (size_t)nin);
    const auto &zout = execute_program(ctx, prog,
                          std::span<const ZKWire>(zin.data(), zin.size()), ws);

    auto dig = std::make_unique<bool[]>(zout.size());
    sess.reveal_bits(dig.get(), PUBLIC, zout.data(), zout.size());
    for (size_t i = 0; i < cout.size(); ++i)
      if ((dig[i] ? 1 : 0) != (cout[i] & 1)) { ++wrong; break; }
  }
  double t = time_from(start);
  sess.finalize();

  if (party == ALICE)
    printf("ZK sha256_256 x%d replays: %.1f ms, %.2f ms/replay, peakRSS %ld MiB, "
           "wrong=%d\n", K, t / 1000.0, t / 1000.0 / K, peak_rss_kib() / 1024, wrong);

  destroy_bool_ios(ios);
  return wrong ? 1 : 0;
}
