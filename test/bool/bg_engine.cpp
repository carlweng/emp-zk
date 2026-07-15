// Background-Ferret bool proof over TWO sockets: the SilentFerret runs on
// `cot_io` (socket A) in a producer thread, streaming COTs through the
// CorrelationPipe, while the engine's own traffic (feeds, gate bits, checks)
// stays on `io` (socket B) — the bool analogue of arith's bg_ostriple.
// Exercises, end-to-end with the malicious batch checks + MAC digest:
//   * split thread budgets (threads vs cot_threads),
//   * the threaded bulk feed (N > kFeedParMin),
//   * the vectorized AND (threaded per-gate compute, crossing CHECK_SZ),
//   * scalar/vector gate interop on the same COT stream,
//   * the threaded PolyProof accumulate (len >= kParMin).
// A second, smaller single-socket pass covers the same threaded paths in
// default (non-background) mode.
//
//   ./run ./build/test_bool_bg_engine [LOG2_N] [THREADS] [COT_THREADS]   (ports P, P+1)
#include "emp-tool/emp-tool.h"
#include <emp-zk/emp-zk.h>
#include <iostream>
#include <memory>
#include <vector>
using namespace emp;
using namespace std;

int party;

static void run_proof(BoolIO *io, BoolIO *cot_io, int party, int64_t N,
                      int threads, int cot_threads, const char *label) {
  auto start = clock_start();
  ZKBoolSession sess(io, party, /*expected_cots=*/0, threads, cot_io,
                     cot_threads);
  cout << "  " << label << " setup: " << time_from(start) / 1000.0
       << " ms  (party " << party << ")" << endl;

  // Fixed-seed witness so both sides can compute the expected outputs.
  block seed = makeBlock(0x0abcdef, 0x7654321);
  PRG prg(&seed);
  auto xa = make_unique<bool[]>((size_t)N);
  auto xb = make_unique<bool[]>((size_t)N);
  prg.random_bool(xa.get(), N);
  prg.random_bool(xb.get(), N);

  start = clock_start();
  // Bulk feeds (N > 1M crosses the kFeedParMin threaded-feed threshold).
  vector<ZKWire> wa = sess.input_bits(ALICE, xa.get(), (size_t)N);
  vector<ZKWire> wb = sess.input_bits(ALICE, xb.get(), (size_t)N);

  vector<block> la((size_t)N), lb((size_t)N), lc((size_t)N);
  for (int64_t i = 0; i < N; ++i) {
    la[(size_t)i] = wa[(size_t)i].label;
    lb[(size_t)i] = wb[(size_t)i].label;
  }

  // Vectorized AND (threaded per-gate compute; crosses CHECK_SZ boundaries
  // when N > 1M). Then a few scalar gates on the same stream to prove the
  // two paths interoperate (same triple buffer, same COT cursor).
  sess.engine().and_block(lc.data(), la.data(), lb.data(), N);
  const int64_t n_scalar = std::min<int64_t>(N, 8);
  for (int64_t i = 0; i < n_scalar; ++i)
    lc[(size_t)i] = sess.engine().and_block(la[(size_t)i], lb[(size_t)i]);

  // Reveal and compare against the cleartext products.
  vector<ZKWire> wc((size_t)N);
  for (int64_t i = 0; i < N; ++i) wc[(size_t)i].label = lc[(size_t)i];
  auto out = make_unique<bool[]>((size_t)N);
  sess.reveal_bits(out.get(), PUBLIC, wc.data(), (size_t)N);
  for (int64_t i = 0; i < N; ++i)
    if (out[(size_t)i] != (xa[(size_t)i] && xb[(size_t)i]))
      error("bg_engine: AND output mismatch");

  // Threaded PolyProof accumulate (len >= PolyProof::kParMin): prove the
  // inner product of the first `sz` witness bits.
  const int64_t sz = std::min<int64_t>(N, 8192);
  bool constant = false;
  for (int64_t i = 0; i < sz; ++i)
    constant = constant != (xa[(size_t)i] && xb[(size_t)i]);
  vector<ZKBit> px((size_t)sz), py((size_t)sz);
  for (int64_t i = 0; i < sz; ++i) {
    px[(size_t)i] = sess.input<ZKBit>(ALICE, xa[(size_t)i]);
    py[(size_t)i] = sess.input<ZKBit>(ALICE, xb[(size_t)i]);
  }
  zkp_inner_prdt(sess, px.data(), py.data(), constant, sz);

  // f2k wires in the same session: exercises the SilentF2kVOLE (sized by
  // cot_threads) on the MAIN socket while the bit-Ferret runs in background
  // mode; the f2k batch check fires at finalize.
  F2kAuthValue fa = sess.engine().f2k_input(makeBlock(0x1234, 0x5678));
  F2kAuthValue fb = sess.engine().f2k_input(makeBlock(0x9abc, 0xdef0));
  F2kAuthValue fc;
  sess.engine().f2k_mul(fc, fa, fb);

  double proof_ms = time_from(start) / 1000.0;
  sess.finalize();
  cout << label << " party " << party << ": N=" << N << " threads=" << threads
       << " cot_threads=" << cot_threads << "  proof " << proof_ms
       << " ms  PASS" << endl;
}

int main(int argc, char **argv) {
  party = parse_party(argv);
  const int64_t N = int64_t{1} << ((argc > 2) ? atoi(argv[2]) : 21);
  const int threads = (argc > 3) ? std::max(1, atoi(argv[3])) : 2;
  const int cot_threads = (argc > 4) ? atoi(argv[4]) : -1; // -1 = same as threads
  const int p = peer_port();

  // TWO connections: main (P) and the dedicated Ferret socket (P+1).
  auto nio = (party == ALICE) ? NetIO::listen(p) : NetIO::connect(peer_ip(), p);
  auto cio = (party == ALICE) ? NetIO::listen(p + 1)
                              : NetIO::connect(peer_ip(), p + 1);
  BoolIO io(nio.get(), party == ALICE);
  BoolIO cot_io(cio.get(), party == ALICE);

  cout << endl << "----- background-Ferret bool proof (two sockets) -----" << endl;
  run_proof(&io, &cot_io, party, N, threads, cot_threads, "bg");
  // Default single-socket mode, same threaded engine paths, same N (so the
  // two modes' proof times are directly comparable in thread sweeps).
  run_proof(&io, nullptr, party, N, threads, cot_threads, "fg");
  return 0;
}
