#pragma once

#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk-arith/int_fp.h"
#include "emp-zk/emp-zk-bool/emp-zk-bool.h"

namespace emp {
using namespace std;

inline IntFp bool2arith(SignedInt &x) {
  IntFp y;
  y.value = EdaBits::conv->bool2arith(x);
  return y;
}

inline void bool2arith(IntFp *y, SignedInt *x, int64_t sz) {
  EdaBits::conv->bool2arith((__uint128_t *)y, x, sz);
}

inline SignedInt arith2bool(IntFp &x) {
  return EdaBits::conv->arith2bool(x.value);
}

inline void arith2bool(SignedInt *y, IntFp *x, int64_t sz) {
  EdaBits::conv->arith2bool(y, (__uint128_t *)x, sz);
}

}  // namespace emp
