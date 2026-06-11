#pragma once

#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk-arith/int_fp.h"
#include "emp-zk/emp-zk-bool/emp-zk-bool.h"

namespace emp {
using namespace std;

inline IntFp bool2arith(ZKInt &x) {
  IntFp y;
  y.value = EdaBits::conv->bool2arith(x);
  return y;
}

inline void bool2arith(IntFp *y, ZKInt *x, int64_t sz) {
  EdaBits::conv->bool2arith((__uint128_t *)y, x, sz);
}

inline ZKInt arith2bool(IntFp &x) {
  return EdaBits::conv->arith2bool(x.value);
}

inline void arith2bool(ZKInt *y, IntFp *x, int64_t sz) {
  EdaBits::conv->arith2bool(y, (__uint128_t *)x, sz);
}

}  // namespace emp
