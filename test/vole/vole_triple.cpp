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

void test_vole_triple(NetIO *ios[threads + 1], int party) {
  VoleTriple<NetIO> vtriple(party, threads, ios);

  uint64_t Delta = 0LL;
  if (party == ALICE) {
    PRG prg;
    prg.random_data(&Delta, sizeof(uint64_t));
    Delta = mod(Delta);
    auto start = clock_start();
    vtriple.setup(Delta);
    std::cout << "setup " << time_from(start) / 1000 << " ms" << std::endl;
    vtriple.check_triple(Delta, vtriple.pre_yz_a, N_PRE_REG_Fp);
  } else {
    auto start = clock_start();
    vtriple.setup();
    std::cout << "setup " << time_from(start) / 1000 << " ms" << std::endl;
    vtriple.check_triple(vtriple.pre_yz_b, N_PRE_REG_Fp);
  }

  int triple_need = vtriple.ot_limit;
  auto start = clock_start();
  if (party == ALICE) {
    uint64_t *buf = new uint64_t[triple_need];
    vtriple.extend(buf, triple_need);
    std::cout << triple_need << "\t" << time_from(start) / 1000 << " ms"
              << std::endl;
    vtriple.check_triple(Delta, buf, triple_need);
    delete[] buf;
  } else {
    __uint128_t *buf = new __uint128_t[triple_need];
    vtriple.extend(buf, triple_need);
    std::cout << triple_need << "\t" << time_from(start) / 1000 << " ms"
              << std::endl;
    vtriple.check_triple(buf, triple_need);
    delete[] buf;
  }

  // triple generation inplace
  uint64_t triple_need_inplace = vtriple.ot_limit;
  uint64_t memory_need = vtriple.byte_memory_need_inplace(triple_need_inplace);
  if(party == ALICE) {
    uint64_t *buf = new uint64_t[memory_need];
    start = clock_start();
    vtriple.extend_inplace(buf, memory_need);
    std::cout << triple_need_inplace << "\tinplace\t" << memory_need << "\t"
              << time_from(start) / 1000 << " ms" << std::endl;
    vtriple.check_triple(Delta, buf, memory_need);
    delete[] buf;
  } else {
    __uint128_t *buf = new __uint128_t[memory_need];
    start = clock_start();
    vtriple.extend_inplace(buf, memory_need);
    std::cout << triple_need_inplace << "\tinplace\t" << memory_need << "\t" << time_from(start) / 1000 << " ms" << std::endl;
    vtriple.check_triple(buf, memory_need);
    delete[] buf;
  }

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
  ;

  test_vole_triple(ios, party);

  for (int i = 0; i < threads; ++i)
    delete ios[i];
  return 0;
}
