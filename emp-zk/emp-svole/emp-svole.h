#ifndef EMP_SVOLE_H__
#define EMP_SVOLE_H__

// FpVOLE moved to emp-ot. This header forwards for back-compat with
// emp-zk consumers; new code should include "emp-ot/svole/fp_vole.h".
#include "emp-ot/svole/fp_vole.h"

// Back-compat for emp-zk consumers that historically relied on the
// `using namespace emp; using namespace std;` at the bottom of the
// old emp-zk/emp-svole/fp_utility.h. Headers in emp-ot deliberately
// avoid this pollution; we restrict it to this back-compat forwarder.
using namespace emp;
using namespace std;

#endif
