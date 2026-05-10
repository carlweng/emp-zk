# emp-zk reorganization plan

Survey-driven proposal for cleaning up the source tree, naming, and a
few cross-module asymmetries that survived the v0.3.x → 1.0 migration.
This file is the working plan; nothing here has been implemented yet.

## Context

Post-migration, the repo has the following peer modules:

```
emp-zk/
    emp-zk-bool/       Boolean ZK (already on the new Backend)
    emp-zk-arith/      Arithmetic ZK (still on its own ZKFpExec singleton)
    emp-vole/          Mod-p VOLE (Wolverine-style)
    emp-vole-f2k/      F_{2^k} VOLE (Quicksilver-style)
    edabit/            bool↔arith conversion (used only by arith)
    extensions/
        floats.h       Fixed-point gadgets (single header)
        lowmc.h        Block cipher (single header)
        ram-zk/        RAM ZK (its own OSTriple, PolyPrdt, three RAM types)
test/
    bool/  arith/  ram/  vole/
```

The tree has three classes of issue: directory layout that no longer
matches what's inside, naming dedup across rings, and one piece of
deferred architectural work (arith hasn't migrated to `Backend`).

---

## 1. Top-level layout reshuffle

### 1.1. `extensions/` is a misleading name

`extensions/` holds three things with very different shapes:

- `extensions/ram-zk/` — 8 files, internal `F2kOSTriple`, `F2kPolyPrdt`,
  three RAM types. **A peer module, not an extension.**
- `extensions/lowmc.h` — circuit description (block cipher).
- `extensions/floats.h` — fixed-point arithmetic gadgets.

**Move to:**

```
emp-zk/ram-zk/             ← promoted out of extensions/
emp-zk/circuits/
    floats.h
    lowmc.h
```

Makes ram-zk symmetric with bool / arith / vole (the other peer modules)
and pulls the two single-file circuit libraries into a clearly-named
subdir.

**Mechanical changes required:**
- Move 8 ram-zk headers, 2 circuit headers
- Update `#include "emp-zk/extensions/ram-zk/..."` → `#include "emp-zk/ram-zk/..."` everywhere
- Update `#include "emp-zk/extensions/{floats,lowmc}.h"` → `#include "emp-zk/circuits/{floats,lowmc}.h"`
- Update `emp-zk/emp-zk.h` umbrella
- Update CMake `install(DIRECTORY ...)` rule (currently catches all of
  `emp-zk/` so this is automatic)

### 1.2. `edabit/` is private to arith

`edabit/` (2 files: `edabits.h`, `auth_helper.h`) is included only by
`emp-zk-arith/zk_fp_exec.h` and exposed via
`setup_zk_arith(..., enable_conversion=true)`. It's not a peer module —
it's an arith-internal mechanism.

**Move to:**

```
emp-zk/emp-zk-arith/edabit/
    edabits.h
    doub_auth_helper.h    (renamed from auth_helper.h to match the class)
```

### 1.3. The two VOLE modules look like duplicates

`emp-vole/` (12 files) and `emp-vole-f2k/` (7 files) have parallel
naming:

| Concept | `emp-vole/` | `emp-vole-f2k/` |
|---|---|---|
| sVOLE | `base_svole.h` | `base_svole.h` |
| LPN | `lpn.h` | `lpn_f2k.h` |
| MPFSS | `mpfss_reg.h` | `mpfss.h` |
| sPFSS sender | `spfss_sender.h` | `spfss_f2k_sender.h` |
| sPFSS receiver | `spfss_recver.h` | `spfss_f2k_recver.h` |

The `_f2k` and `_reg` suffixes exist purely because two files at the
same level had the same role.

**Collapse into one VOLE tree with ring-tagged subdirs:**

```
emp-zk/vole/
    common/       preot.h, base_cot.h, twokeyprp.h, utility.h (cross-ring)
    prime/        cope.h, base_svole.h, lpn.h, mpfss_reg.h, ...
    f2k/          base_svole.h, lpn.h, mpfss.h, spfss_{sender,recver}.h, ...
    emp-vole.h    umbrella
```

`prime/` and `f2k/` use the **same** file names — context-disambiguated
by the path.

**Tradeoff:** ~30 files of `#include` rewrites. Bulk-mechanical. Worth
doing once.

### 1.4. `data/` at top-level is runtime state

`data/` holds only `.keep` and ignores `pre_ot_data_reg_{send,recv}`
(FerretCOT preprocessing artifacts produced by tests). Belongs under
`build/` or `${CMAKE_CURRENT_BINARY_DIR}/data/`, not the source tree.

**Fix:** in `test/CMakeLists.txt` add
`file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/data)`, define
`EMP_ZK_DATA_DIR` to point there, update tests that hardcode `./data/`
paths to use the macro. Then delete top-level `data/.keep`.

---

## 2. Naming dedup — the "OSTriple problem"

There are three classes named `*OSTriple` that mean the same
architectural thing (the authenticated-triple stream backing a ZK
protocol) over different rings:

| File | Class | Ring | LOC |
|---|---|---|---|
| `emp-zk-bool/ostriple.h` | `OSTriple` | F₂ | 302 |
| `emp-zk-arith/ostriple.h` | `FpOSTriple<IO>` | F_p | 522 |
| `extensions/ram-zk/ostriple.h` | `F2kOSTriple<IO>` | F_{2^k} | 349 |

Same story:
- `bool/polynomial.h` → `PolyProof`
- `arith/polynomial.h` → `FpPolyProof<IO>`
- `ram-zk/poly_prdt.h` → `F2kPolyPrdt<IO>`

And:
- bool: `TripleAuth` (now folded into `OSTriple`)
- arith: `FpAuthHelper<IO>` in `arith/triple_auth.h`
- edabit: `DoubAuthHelper<IO>` in `edabit/auth_helper.h`

### 2.1. Option 1 (preferred): same name, namespace-disambiguated

Rename the classes to drop the prefix; place each in its own namespace:

```
emp-zk/bool/ostriple.h:    namespace emp::bool_zk  { class OSTriple; }
emp-zk/arith/ostriple.h:   namespace emp::arith_zk { class OSTriple<IO>; }
emp-zk/ram-zk/ostriple.h:  namespace emp::ram_zk   { class OSTriple<IO>; }
```

Callers reach in by qualified name (`emp::arith_zk::OSTriple`).

- **Pro:** symmetry visible in the tree; the type signature (or the
  qualified name) already implies the ring.
- **Pro:** matches how emp-tool spells `HalfGate{Gen,Eva}` vs
  `ClearBackend` — same pattern, no manual prefixes.
- **Con:** namespace work; one-time mechanical cost touching every
  cross-module call.

### 2.2. Option 2 (rejected): collocate, keep prefix names

```
emp-zk/protocol/
    ostriple_f2.h    (was bool/ostriple.h)
    ostriple_fp.h    (was arith/ostriple.h)
    ostriple_f2k.h   (was ram-zk/ostriple.h)
    ...
```

- **Pro:** one `grep` finds all OSTriple variants.
- **Con:** crosses module boundaries — bool/arith/ram-zk all depend
  on `protocol/`. Not a clean module shape.

**Recommendation: Option 1.**

---

## 3. Architectural alignment

### 3.1. arith hasn't migrated to `Backend* backend` yet

The README banner already calls this out as deferred:
`arith/zk_fp_exec.h:14` declares `static ZKFpExec *zk_exec` — its own
static singleton, parallel to the bool side which now plugs into the
global `Backend`.

Two consequences:

1. emp-tool main **already supports both bool and arith on Backend**:
   `Backend::feed(void*, ...)` and `reveal(bool*, ...)` use `void*` and
   a `wire_bytes()` virtual exactly so a `Bit_T<__uint128_t>` arith
   wire works. The migration mirrors what we just did for bool:
   collapse `ZKFpExec/Prv/Ver` into `ZKArithBackend{Prv,Ver}` plugged
   into `backend`.

2. After migration: `setup_zk_arith` no longer needs the
   `enable_conversion` mode-switch — it can detect a bool backend by
   examining `backend->wire_bytes() == sizeof(block)` and conditionally
   install an edabit conversion path.

This is the next natural pass — same shape as the bool migration we
just completed.

**Open question:** can both backends be installed at once? In v0.3.x
they were separate singletons (`circ_exec`, `zk_exec`) so coexistence
was implicit. With one global `Backend* backend`, you need either:
(a) a "compound" backend that delegates per wire-type, or (b) a
context manager that swaps `backend` on entry/exit of bool/arith
gadgets. Worth thinking through before starting.

### 3.2. The three "batched random-linear-combination" checks are the same

`bool/ostriple.h::andgate_correctness_check_manage`,
`arith/ostriple.h::FpOSTriple::check_zero`, and
`ram-zk/ostriple.h::F2kOSTriple::batch_check` all implement:

1. Stash (left, right, output) triples in three buffers
2. At flush time, hash-derive a coefficient seed from the wire-byte
   transcript
3. Compute random-linear-combination of triples, reduce, exchange,
   compare

A `BatchedTripleCheck<Field>` template parameterized by field ops would
deduplicate ~150 LOC. But this is a real refactor (touches the
cryptographic core) — flag for later, **not** part of this reorg.

---

## 4. Ergonomic / hygiene

### 4.1. The `run` script

`run` is a 25-line bash wrapper that drives 2-party tests by spawning
two processes on hardcoded port 12345 with `-p1 / -p2 / -m1 / -m2 /
-t1 / -t2` flags for perf / valgrind / time variants. Used by every
`add_test_case_with_run` line in `test/CMakeLists.txt`.

Issues:
- Hardcoded port collides if tests run in parallel
- The flag-dispatch shape means CTest can't pass arguments through
  cleanly
- Bug in `-p2`: `(perf record $1 2 12345)` lacks the sleep guard, so
  it can race the listener

**Replace with** a Python script or CMake-side
`run_two_party.cmake.in` helper that:
- Picks a port from `${CMAKE_CURRENT_BUILD_DIR}` test env (or a
  counter)
- Runs both parties, captures both outputs
- Returns nonzero if either errored

### 4.2. Move the umbrella header inward

`emp-zk/emp-zk.h` pulls in every module. A user only doing bool ZK
pays the compile cost of arith + vole-f2k + ram + lowmc + floats.

**Add fine-grained headers:**

```
emp-zk/bool.h        bool only
emp-zk/arith.h       arith (+ edabit if conversion enabled)
emp-zk/ram-zk.h      ram only
emp-zk.h             kitchen sink (existing — still works for old callers)
```

### 4.3. Test file organization

`test/` is structured by ring (bool / arith / ram / vole), but:
- VOLE-f2k tests live in `test/vole/` mixed with classical-VOLE tests
  (`vole_f2k_triple.cpp` next to `vole_triple.cpp`)
- arith's `abconversion.cpp` is the edabit test, not really an arith
  primitive
- There's no `test/edabit/`, `test/circuits/`

**After the source reorg above:**

```
test/bool/                  unchanged
test/arith/                 keep arith primitives
test/arith/edabit/          move abconversion.cpp here
test/ram-zk/                renamed from test/ram/
test/vole/prime/            cope, base_svole, lpn, vole_triple
test/vole/f2k/              vole_f2k_triple, base_svole_f2k...
test/circuits/              lowmc, sha256 (move from test/bool/)
```

---

## ROI ordering / what to do first

1. **§1.1 + §1.2 (ram-zk promotion + edabit move into arith).** Tree
   clarity win, low-risk mechanical moves. ~3h including all `#include`
   updates and CMake fixup.

2. **§2.1 (same-name class dedup with namespaces).** Drops the
   `Fp` / `F2k` prefixes. Mostly mechanical sed work, biggest
   readability impact across rings.

3. **§3.1 (arith → Backend migration).** Natural next step in the
   toolkit-wide alignment. Larger, but the bool pass we just landed is
   the template — same shape applies.

4. **§1.3 (VOLE tree consolidation).** High LOC churn (renames hit
   every cross-module include) for marginal payoff. Defer until
   something else forces touching those files.

5. **§4.1 (replace `run` script).** Small win, do it whenever someone
   touches the test wrapper for another reason.

6. **§4.2 + §4.3 + §1.4 (umbrella headers, test reorg, data/ move).**
   Cleanup grade — bundle into one PR after the bigger changes settle.

7. **§3.2 (batched check dedup).** Real cryptographic refactor.
   Defer indefinitely — not blocking anything, and the three
   implementations have drifted enough that unification needs
   cross-ring testing.

The first two together would land the repo in the same shape as
emp-tool / emp-ot main — clear peer modules at the top, ring-
disambiguated by namespace within.
