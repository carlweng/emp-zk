#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk.h"
#if defined(__linux__)
#include <sys/time.h>
#include <sys/resource.h>
#elif defined(__APPLE__)
#include <unistd.h>
#include <sys/resource.h>
#include <mach/mach.h>
#endif

using namespace emp;
using namespace std;

int party, port;
const int threads = 4;

void check_triple(NetIO *io, uint64_t delta,
                  const uint64_t *val, const uint64_t *mac, int64_t size) {
  if (party == ALICE) {
    io->send_data(&delta, sizeof(uint64_t));
    io->send_data(mac, size * sizeof(uint64_t));
    io->flush();
  } else {
    uint64_t delta_;
    std::vector<uint64_t> mac_alice(size);
    io->recv_data(&delta_, sizeof(uint64_t));
    io->recv_data(mac_alice.data(), size * sizeof(uint64_t));
    for (int64_t i = 0; i < size; ++i) {
      uint64_t tmp = mult_mod(delta_, val[i]);
      tmp = add_mod(tmp, mac_alice[i]);
      if (tmp != mac[i]) {
        std::cout << "triple error at " << i << std::endl;
        abort();
      }
    }
  }
}

void test_vole_triple(NetIO *ios[threads + 1], int party) {
  FpVOLE<AuthValueFp> vtriple(party, ios[0]);
  uint64_t Delta = 0;
  if (party == ALICE) {
    PRG prg;
    prg.random_data_unaligned(&Delta, sizeof(uint64_t));
    Delta = mod(Delta);
    if (Delta == 0) Delta = 1;
    vtriple.set_delta(Delta);
  }

  auto start = clock_start();
  const int64_t triple_need = vtriple.chunk_aligned_buf_sz();
  std::vector<AuthValueFp> buf(triple_need);
  vtriple.run(buf.data(), triple_need);
  std::cout << triple_need << "\t" << time_from(start) / 1000 << " ms"
            << std::endl;

  std::vector<uint64_t> buf_val(triple_need), buf_mac(triple_need);
  for (int64_t i = 0; i < triple_need; ++i) {
    buf_val[i] = buf[i].val;
    buf_mac[i] = buf[i].mac;
  }
  check_triple(ios[0], Delta, buf_val.data(), buf_mac.data(), triple_need);

#if defined(__linux__)
  struct rusage rusage;
  if (!getrusage(RUSAGE_SELF, &rusage))
    std::cout << "[Linux]Peak resident set size: " << (size_t)rusage.ru_maxrss
              << std::endl;
  else
    std::cout << "[Linux]Query RSS failed" << std::endl;
#elif defined(__APPLE__)
  struct mach_task_basic_info info;
  mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
  if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info,
                &count) == KERN_SUCCESS)
    std::cout << "[Mac]Peak resident set size: "
              << (size_t)info.resident_size_max << std::endl;
  else
    std::cout << "[Mac]Query RSS failed" << std::endl;
#endif
}

int main(int argc, char **argv) {
  parse_party_and_port(argv, &party, &port);
  NetIO *ios[threads];
  for (int i = 0; i < threads; ++i)
    ios[i] = new NetIO(party == ALICE ? nullptr : "127.0.0.1", port + i);

  std::cout << std::endl
            << "------------ VOLE field ------------" << std::endl
            << std::endl;

  test_vole_triple(ios, party);

  for (int i = 0; i < threads; ++i)
    delete ios[i];
  return 0;
}
