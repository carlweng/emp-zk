#ifndef __EMP_ZK_FLOAT_
#define __EMP_ZK_FLOAT_

// Float<->Integer fixed-point bridge. Ported to the new circuits API:
//   - Integer = SignedInt; resize() is single-arg + sign-extends, so
//     zero-extension goes via as_unsigned().resize().
//   - The 3-arg `If(sel, then_v, else_v)` was replaced by the fluent
//     `If(cond).Then(then_v).Else(else_v)` builder in
//     emp-tool/circuits/sortable.h.
//   - `leading_zeros()` is only on UnsignedInt; route through
//     `as_unsigned()` and re-wrap into Integer.

#include "emp-tool/emp-tool.h"
#include <iostream>
using namespace emp;
using namespace std;

inline Integer FloatToInt62(Float input, int s) {
  Integer fraction(25, 0, PUBLIC);
  memcpy(fraction.bits.data(), input.value.data(), 23 * sizeof(block));
  fraction[23] = Bit(true, PUBLIC);
  fraction = Integer(fraction.as_unsigned().resize(61));

  Integer exp(8, 0, PUBLIC);
  memcpy(exp.bits.data(), input.value.data() + 23, 8 * sizeof(block));
  exp = exp - Integer(8, 127 + 23 - s, PUBLIC);
  Integer negexp = -exp;
  fraction = If(!exp[7])
                 .Then(fraction << exp.as_unsigned())
                 .Else(fraction >> negexp.as_unsigned());
  fraction = If(negexp >= Integer(8, 61, PUBLIC))
                 .Then(Integer(61, 0, PUBLIC))
                 .Else(fraction);
  fraction = If(input[31]).Then(-fraction).Else(fraction);
  fraction = Integer(fraction.as_unsigned().resize(62));
  return fraction;
}

inline Float Int62ToFloat(Integer input, int s) {
  input = If(input > Integer(62, (int64_t)((1ULL << 60) - 1), PUBLIC))
              .Then(input - Integer(62, (int64_t)((1ULL << 61) - 1), PUBLIC))
              .Else(input);
  input.bits.pop_back();
  assert(input.size() == 61);
  const Integer twentyThree(8, 23, PUBLIC);

  Float output(0.0, PUBLIC);
  Bit signBit = input.bits[60];
  UnsignedInt unsignedInput = input.abs();

  Integer firstOneIdx = Integer(8, 60, PUBLIC) -
                        Integer(unsignedInput.leading_zeros().resize(8));
  Bit leftShift = firstOneIdx >= twentyThree;
  Integer shiftOffset = If(leftShift)
                            .Then(firstOneIdx - twentyThree)
                            .Else(twentyThree - firstOneIdx);
  Integer shifted = If(leftShift)
                        .Then(Integer(unsignedInput << shiftOffset.as_unsigned()))
                        .Else(Integer(unsignedInput >> shiftOffset.as_unsigned()));
  Integer exponent = firstOneIdx + Integer(8, 127 - s, PUBLIC);

  output.value[31] = signBit;
  memcpy(output.value.data() + 23, exponent.bits.data(), 8 * sizeof(block));
  memcpy(output.value.data(), shifted.bits.data(), 23 * sizeof(block));
  return output;
}

#endif //__EMP_ZK_FLOAT_
