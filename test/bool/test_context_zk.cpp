// Circuits expressed over the emp-tool BooleanContext, executed in zero knowledge
// on emp-zk-bool through ZKBoolContext / ZKBoolSession. Proves (1) a Ctx-templated
// typed kernel (UInt32 add) run in ZK via the session's generic input/reveal, and
// (2) an IR-replay builtin (sha256_256) run over the ZK context, validated
// bit-for-bit against a ClearCtx replay of the same circuit. C++20.

#include "../test_io_helpers.h"
#include "emp-tool/emp-tool.h"
#include "emp-tool/ir/context/clear.h"   // ClearCtx
#include "emp-tool/ir/builtins.h"        // circuit::builtin_circuit
#include "emp-tool/ir/execute.h"         // execute_program
#include <emp-zk/emp-zk.h>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <span>
#include <vector>

using namespace emp;

int port, party;
const int threads = 1;
static int fails = 0;

// Feed cleartext bits as authenticated ZK wires owned by `owner` (ALICE witness
// or PUBLIC); the raw Ctx::Wire form execute_program consumes. Routes through the
// session's raw-bit boundary (no reaching into the engine).
static std::vector<ZKWire> feed_wires(ZKBoolSession &sess, int owner,
                                      const std::vector<uint8_t> &bits) {
  const int n = (int)bits.size();
  auto b = std::make_unique<bool[]>((size_t)n);
  for (int i = 0; i < n; ++i) b[(size_t)i] = bits[(size_t)i] != 0;
  return sess.input_bits(owner, b.get(), (size_t)n);
}
static std::vector<uint8_t> reveal_wires(ZKBoolSession &sess, int recipient,
                                         const std::vector<ZKWire> &w) {
  const int n = (int)w.size();
  auto b = std::make_unique<bool[]>((size_t)n);
  sess.reveal_bits(b.get(), recipient, w.data(), (size_t)n);
  std::vector<uint8_t> out((size_t)n);
  for (int i = 0; i < n; ++i) out[(size_t)i] = b[(size_t)i] ? 1 : 0;
  return out;
}

void run(BoolIO *ios[threads], int party) {
  ZKBoolSession sess(ios[0], party);
  ZKBoolContext &ctx = sess.ctx();

  // (1) Typed UInt32 add over the ZK context, via the session's generic
  // WireValue input/reveal (UInt_T<ZKBoolContext,32>).
  using U32 = UInt_T<ZKBoolContext, 32>;
  const uint32_t x = 0x12345678u, y = 0x9abcdef0u;
  U32 a = sess.input<U32>(ALICE, x);
  U32 b = sess.input<U32>(ALICE, y);
  uint32_t got = (uint32_t)sess.reveal(a + b, PUBLIC).value_or(0);
  if (got != (uint32_t)(x + y)) {
    ++fails;
    printf("UInt32 add over ZK: got %u want %u\n", got, (uint32_t)(x + y));
  }

  // (2) IR replay of the sha256_256 builtin over the ZK context, validated
  // against a ClearCtx replay of the SAME .empbc on the same (test) witness.
  const circuit::BooleanProgram &prog = circuit::builtin_circuit("sha256_256");
  const int nin = (int)prog.num_inputs;
  std::vector<uint8_t> wit((size_t)nin);
  for (int i = 0; i < nin; ++i)                // deterministic test witness
    wit[(size_t)i] = (uint8_t)(((uint32_t)i * 2654435761u) >> 17) & 1u;

  auto zin = feed_wires(sess, ALICE, wit);
  auto zout = execute_program(ctx, prog,
                              std::span<const ZKWire>(zin.data(), zin.size()));
  auto zdig = reveal_wires(sess, PUBLIC, zout);

  ClearCtx cctx;
  auto cout = execute_program(cctx, prog,
                              std::span<const uint8_t>(wit.data(), (size_t)nin));
  for (size_t i = 0; i < cout.size(); ++i)
    if ((zdig[i] & 1) != (cout[i] & 1)) {
      ++fails;
      printf("sha256_256 ZK-vs-ClearCtx replay mismatch at bit %zu\n", i);
      break;
    }

  sess.finalize();
  if (party == ALICE)
    printf("test_context_zk: %s\n",
           fails ? "FAILED"
                 : "BooleanContext over ZK (UInt32 add + sha256_256 replay) — PASS");
}

int main(int argc, char **argv) {
  parse_party_and_port(argv, &party, &port);
  BoolIO *ios[threads];
  make_bool_ios(ios, party, port);
  run(ios, party);
  destroy_bool_ios(ios);
  return fails ? 1 : 0;
}
