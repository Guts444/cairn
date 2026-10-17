# Keyed additions and initial differential analysis, 2026-10-17

Cairn v0.1 remains frozen. This report adds mathematical results, executable
checks and a small bounded search. It is author-side analysis with AI assistance,
not independent cryptographic review. The earlier [findings](FINDINGS.md),
[measurements](results.json) and [release provenance](../docs/PROVENANCE.md) remain
intact. No challenge key, challenge plaintext or 16-round break was recovered.

The main results are:

* **Exact classification:** F is XOR-affine iff both subkeys are multiples of
  2^62. Only (0,0) makes F XOR-linear. These pairs are reachable at any specified
  round through the actual schedule, with exactly 2^128 master keys per pair.
* **Exact carry model:** fixed-constant addition counts, signed masked counts,
  and a budgeted joint count for the two additions. A 64-bit counterexample
  shows why multiplying single-addition probabilities can be wrong by 61 bits.
* **An explanation of the four-round parity bias:** tight, mathematically
  justified fixed-key probability intervals, confirmed on fresh plaintexts.
* **A better selected-key four-round endpoint:** 108 hits in 2^20 held-out
  pairs, versus 44 for the previous endpoint on the same pairs. This is an
  observation, not an exact four-round probability or an arbitrary-key attack.
* Bounded candidate exploration through 16 rounds, with explicit local bounds
  and dependency warnings. **No global differential-probability bound** is
  established at any multi-round count.

Code: [`structural.py`](structural.py), [`structural_followup.py`](structural_followup.py).
Exact fractions, full candidate paths and counts:
[`structural-results.json`](structural-results.json),
[`structural-followup-results.json`](structural-followup-results.json).
The [schematics](../docs/SCHEMATICS.md) show all operation ordering and widths.

## 1. Definitions and established methods

All words in the actual cipher are 64 bits; bit 0 is least significant. Write
`A_k(x)=x+k mod 2^64`, `P=I XOR ROL13 XOR ROL37`,
`Q=I XOR ROL17 XOR ROL41`, and `S=ROL29 o Q`. Then

```text
F_(u,v) = S o A_v o P o A_u.
```

P^8=Q^8=I: in characteristic two, P^8=I XOR ROL104 XOR ROL296,
and both rotations reduce to ROL40. The same calculation gives two ROL8
terms for Q. Hence P, Q, S and every keyed F are permutations.

The methodological starting points are
[Biham and Shamir, differential cryptanalysis of DES-like cryptosystems](https://link.springer.com/article/10.1007/BF00630563),
[Matsui's differential/linear characteristic search](https://link.springer.com/chapter/10.1007/BFb0053451),
and [Matsui's linear cryptanalysis](https://link.springer.com/chapter/10.1007/3-540-48285-7_33).
Here a **characteristic/trail** fixes intermediate differences; a **differential**
fixes only endpoints and sums over compatible trails. A parity of an output
difference is a differential-linear/autocorrelation statistic, not an exact
output differential or an ordinary plaintext/ciphertext linear approximation.

[Lipmaa and Moriai](https://eprint.iacr.org/2001/001) study differential
properties of modular addition. Cairn needs the fixed-constant case, not a
model that averages over a fresh random addend for every operation.
[Leurent's ARX toolkit](https://who.paris.inria.fr/Gaetan.Leurent/arxtools.html)
motivates finite-state carry propagation and richer value constraints.
[Song, Huang and Yang](https://eprint.iacr.org/2016/209) give automated ARX
characteristic search and differential clustering methods.
[Xu et al.](https://eprint.iacr.org/2022/135) explicitly demonstrate failures of
Markov/independence assumptions in ARX characteristic probabilities.
These works guide the method; none evaluates Cairn or supplies a security bound
for it. Publisher abstracts were used for the historical Matsui/Biham references;
the carry recurrence and Cairn-specific proofs are given explicitly below.

Matsui-style branch-and-bound would need admissible suffix bounds to certify
optimality. A SAT/SMT paired-execution model can validate existence while retaining
actual word values and round keys; SAT alone does not count plaintexts. Weighted
model counting, #SAT or exact constraint propagation is needed for probabilities.
MILP is possible after encoding the Boolean carry relations and key bits, but
integer addition weights from an independent-addition model would be unjustified.
This first stage uses a four-state automaton and binary affine-system counting
instead of starting with expensive solver runs.

## 2. Exactly which round keys are affine?

Here affine means `f(x)=B*x XOR c` over GF(2); linear additionally requires c=0.

### Constant-addition lemma

For nonzero n-bit k, let t be the index of its least significant set bit.
Adding k leaves bits below t unchanged, flips bit t, and introduces carries
above it. For output bit j>t, the carry polynomial has degree j-t and its
highest-degree monomial is `x_t*x_(t+1)*...*x_(j-1)`, with coefficient one.
This follows by induction from the binary carry recurrence: at bit t the
outgoing carry is x_t; each subsequent carry's highest-degree term is the
incoming term multiplied by x_j, irrespective of k_j. The output also contains
the degree-one term x_j. Thus

```text
degree(A_k) = max(1, n-1-t).
```

Consequently A_k is affine iff k is a multiple of 2^(n-2), including k=0.
For 64 bits the four values are 0, 2^62, 2^63 and 3*2^62. For example,
adding 2^62 flips bit 62 and XORs the old bit 62 into bit 63; it is affine,
despite having a carry. Calling every nonzero addition nonlinear is incorrect.
Only A_0 is linear, because A_k(0)=k.

### No hidden cancellation between Cairn's additions

S is invertible linear, so F is affine iff `A_v P A_u` is affine. Suppose this
composition is an invertible affine map B. Then

```text
P A_u = A_(-v) B.
```

Invertible affine substitution preserves algebraic degree. If either addition
is non-affine, both sides must have the same degree D>=2, so the valuations of
u and -v coincide. In A_u, only output bit 63 has degree D. Therefore the
degree-D homogeneous part of `P A_u` has nonzero coordinates **12, 36 and 63**.
On the right, only output bit 63 of `A_(-v) B` can have degree D; every other
coordinate has smaller degree even after affine input substitution. This is a
contradiction. If just one addition is affine, degree preservation already gives
a contradiction. Conversely, composing affine maps is affine. Hence

```text
F_(u,v) is affine  <=>  u == v == 0 modulo 2^62.
```

For these 16 pairs, F(0)=0 iff `v=-P(u) mod 2^64`. Let H be the span of bits
62 and 63. For nonzero u in H, P(u) has nonzero lower bits among 11,12,35,36;
these cannot all cancel. Since H is closed under modular negation, v cannot
also lie in H. Thus **F is linear iff u=v=0**, without exceptions from
non-affine cancellation. The executable checks verify every pair at five-bit
toy width and all 16 affine cases at real width; the proof establishes the
64-bit classification, not the finite tests alone.

### Other locally weak structures

High divisibility by powers of two shortens the nonlinear carry chain. If both
u,v are divisible by 2^61, each addition has degree at most two and F has degree
at most four. This is a degree upper bound, not a multi-round attack. More
generally the first t+2 output bits of A_k are affine when v2(k)=t (truncate at
64). Its low t bits are identity bits, and every constant addition has the
deterministic top-bit differential `2^63 -> 2^63` with probability one.

An affine F has probability-one output differences for every input difference
and corresponding magnitude-one linear correlations with the appropriate
input/output masks. A nonlinear F still has some exact bit relations; there is
no established uniform bound here on its maximum differential probability or
maximum linear correlation. The fixed-key counts below expose more structure
than treating nonzero round keys as interchangeable random nonlinear functions.

## 3. Reachability through the actual 256-bit schedule

Each schedule iteration is a permutation of its four-word state, even though
it emits only 128 bits. Given its post-permutation state `(a',b',c',d')`, undo it
by naming `(B,C,D,A)=(a',b',c',d')`, then

```text
b = ROR(B,17) XOR D
d = D - ROL(C,31)
c = C XOR ROL(A,23)
a = A - ROL(b,9) - ((i+1)*G)
```

All subtractions are modulo 2^64. A desired emitted pair (u,v) has precisely
the post-iteration states

```text
(a',b',c',d') = (a', b', a' XOR u, v-b'),
```

where a',b' are arbitrary. Undo iterations `8+j, ..., 0` to get a master key
whose round j pair is exactly (u,v), including all eight warmups and real
constants. There are exactly **2^128 such master keys per specified pair and
round**, since the entire state mapping is bijective.

Under a uniform master key, each single emitted pair is uniform on 128 bits.
At a specified round the affine-pair event therefore has probability 2^-124;
the zero pair has probability 2^-128. A union bound over 16 rounds is at most
2^-120 for at least one affine F. This is a bound on this narrowly defined
structural event, **not** on full-cipher attacks or all weak keys. Round-pair
events are not shown independent. The degree-at-most-four pair family above
has single-round prevalence 2^-122.

One public example producing (0,0) at round index 0 is

```text
7ade81addea056088455532da696efb5a4886a32ac996cfe8f18cedab780a00a
```

The results include examples at indices 0,7,15. The full schedule for each
example has just the specified affine round. Reproduction constructs all 16
affine pairs at each of those indices and checks the original `expand_key`.
These are genuine reachable classes of **one affine round**, not a class of
fully affine encryptions. We have not characterized simultaneous affine rounds,
related-key trails, or an exploitable weak-master-key class for all 16 rounds.
An affine round propagates differences deterministically for that round; later
non-affine rounds need separate analysis.

## 4. Exact fixed-key XOR-difference model

For the addition `z=x+k`, compare x and x'=x XOR alpha. At bit i let c_i,d_i be
the two incoming carry bits (c_0=d_0=0). For each possible x_i in {0,1},

```text
beta_i = alpha_i XOR c_i XOR d_i
c_(i+1) = floor((x_i + k_i + c_i)/2)
d_(i+1) = floor(((x_i XOR alpha_i) + k_i + d_i)/2).
```

Keep only edges matching the specified beta_i, add integer counts per paired
carry state, and discard final carries. Sum final counts and divide by 2^64.
This is an O(64) exact calculation for every fixed (alpha,beta,k), including
impossible differences and probabilities not restricted to powers of two.
Weight each edge by `(-1)^(mask_i*beta_i)` instead of filtering it to obtain
the exact signed masked count, also in O(64).

### Retaining dependencies within F

An internal round trail fixes alpha before A_u, beta after A_u, and gamma after
A_v; the output difference is S(gamma). Its probability is a joint event:

```text
J = Pr_r[ A_u(r) XOR A_u(r XOR alpha) = beta
          AND A_v(P(A_u(r))) XOR A_v(P(A_u(r XOR alpha))) = gamma ].
```

Change variable to x=A_u(r), a uniform word. The first event becomes a
differential of A_(-u) with input beta and output alpha. A reduced binary
decision diagram of each addition's four-state automaton gives disjoint bit
cubes of accepted inputs. Intersect first-event cubes on x with second-event
cubes on P(x). Every intersection is a binary affine system, counted by
Gaussian elimination: zero if inconsistent, otherwise 2^(64-rank). Disjointness
allows summation without double counting. P's wraparound rotations are included.

If either addition event is universal, the other event's marginal count is
already exact (P is invertible). Otherwise the implementation caps each cube
cover at 256. If that cap is exceeded, it returns **no exact joint count**.
Using the exact marginal probabilities p1,p2, valid fallback bounds are

```text
max(0,p1+p2-1) <= J <= min(p1,p2).
```

Both events are measured on the same uniform x, with P a permutation. The
fallback p1*p2 is used only as a **search score**, explicitly labeled in JSON.
It is neither an upper nor a lower bound.

### Real-width dependence counterexample

Take `u=ffffffffffffffff`, `v=1`, `alpha=ffffffffffffffff`, `beta=1`, and
`gamma=ffffffdfffffdfff`. Each addition marginal has count 4 out of 2^64, but
the joint count is **2 out of 2^64**. Multiplying marginals would give 2^-124
instead of 2^-63, a factor of 2^61. The code supplies a master key emitting
this exact pair at round 0. This is an internal round characteristic, not a
claim that the complete endpoint differential has exactly that probability.
It illustrates a modeling failure; a probability of 2^-63 is not itself a
practical full-cipher attack.

Validation exhausts all 4,096 fixed-addition equations at four-bit width, all
4,096 masked signed-count equations, and every beta/gamma pair for 64 selected
five-bit (alpha,u,v) cases (65,536 joint equations). Cube membership is checked
on every four-bit input. Five-bit rotations are reduced modulo five and do not
represent reduced-round 64-bit security. Real-width checks cover the counterexample,
top-bit deterministic differences, both linear-layer orders, affine functions,
schedule inversion and agreement with the frozen scalar F.

## 5. Why the three-/four-round results occur

For input difference (h,0), h=2^63, the difference states are

```text
after round 0: (0,h)
after round 1: (h,D1)
after round 2: (D1,h XOR D2)
after round 3: (h XOR D2, ...),
```

where D1 is an F_1 difference with input h, and D2 an F_2 difference with
input D1. Indices here start at zero. The three-round left-half constraint
from [FINDINGS.md](FINDINGS.md) follows because the first addition preserves h,
P(h) has no bits below 12, and the second addition cannot introduce differences
below that position. The constraint is truncated, so it does not identify one
high-probability full output difference.

For four rounds the old statistic is `parity(m AND (h XOR D2))`, where
`m=9da28b88c58ab380`. The mask satisfies `<m,S(z)>=z_1`. Bit 1 of addition
by v has derivative

```text
Delta(A_v(y))_1 = Delta y_1 XOR (v_0 AND Delta y_0).
```

Thus its mask before A_v is `e1 XOR v_0*e0`. Pull this mask back through P to
get a fixed mask on the output of A_u. The signed carry automaton above computes
its exact autocorrelation for any input difference.

The base words R_1,R_2 are independent uniform 64-bit words for every fixed key:
the map from the plaintext to any consecutive Feistel right words is bijective.
Therefore the first active round's difference D1 can be averaged against the
second active round's autocorrelation **without an independence assumption**.
Its distribution is especially tractable: A_u preserves h, so

```text
Pr[D1=S(gamma)] = DP_(v1)(P(h) -> gamma),
C4 = (-1)^<m,h> * sum_gamma Pr[D1=S(gamma)]
                     * AC_(u2)(S(gamma), P^T(e1 XOR (v2_0)*e0)).
Pr[old parity is one] = (1-C4)/2.
```

Here AC is the normalized signed addition count. Only v1, u2 and bit 0 of v2
enter this four-round statistic; u1 and the other round keys drop out. This
is a structural explanation for the old experiment, not a fresh mask search.

Enumerate 256 retained gamma outcomes with exact counts. The omitted probability
mass epsilon is known exactly because these outcomes are disjoint. Each missing
correlation is in [-1,1], so its contribution to C4 is bounded by epsilon.
This gives rigorous probability intervals, regardless of whether the retained
outcomes are the globally most probable ones:

| Public key | Proven probability interval for parity=1 | Held-out ones / 2^20 |
| --- | --- | --- |
| `bytes(range(32))` | [0.969511555490733, 0.969514917639616] | 1,016,407 |
| Previous selected four-round key | [0.970703362790649, 0.970706089447567] | 1,017,839 |

Decimal endpoints are rounded outwards; JSON stores exact fractions. Interval
widths are about 3.36e-6 and 2.73e-6. The observed rates fluctuate around the
analytical prediction; a sample rate need not lie in an interval for the true
probability. These are fixed-key bounds on **one parity statistic**, not bounds
on all four-round differential probabilities.

At five rounds the left difference is `D1 XOR D3`, where the input difference
to F_3 is `h XOR D2`. The base word R_3 is `R_1 XOR F_2(R_2)`; it is not a
fresh independent variable after conditioning on D1 and D2. The four-round
factorization therefore does not extend by appending another marginal.
The previously observed opposite-sign five-round biases remain unexplained
quantitatively. A value-aware joint model of these two base words is the next
useful target. We do not claim to have derived the five-round probability.

## 6. Bounded searches and defensible multi-round bounds

Two public master keys and two input differences are explored. The inputs are
the earlier (h,0) relation and the selected-key skeleton input `(S(P(h)),h)`.
The actual 16-pair schedule is expanded once per master key, with no invented
or independently sampled round keys. Each addition's output-prefix beam retains
8 prefixes and supplies 2 complete outcomes. A Feistel beam retains 4 candidates.
The search is deterministic, with finite operation/representation budgets; no
long solver timeout is used as evidence.

An exact local count is used when available; otherwise the search score uses
the product of addition marginals. Round scores are also multiplied to rank
candidates. **These products are not multi-round probabilities.** There is no
certificate of optimality even within all trails for these input differences;
pruning occurs at both the bit and round levels. At 16 rounds several scores
are below 2^-128, smaller than the probability of even one plaintext in the
128-bit domain. They can only be scores; some candidates may be impossible.
Only witnessed paths are called confirmed characteristics here.

A modest but rigorous bound is available for each listed internal candidate.
Define E_i as its specified round event evaluated on the base right word R_i.
The full trail event is the intersection of these E_i. Adjacent R_i,R_(i+1)
are independent uniform words. Moreover, because F_(i+1) is a permutation,
R_i and R_(i+2) are also independent: recover the intermediate right word
from `R_(i+2) XOR R_i` by inverting F_(i+1). Thus

```text
Pr[complete specified trail] <= min_i U_i
Pr[complete specified trail] <= U_i*U_j for 1 <= j-i <= 2,
```

where U_i is an exact local probability or the valid local upper bound above.
Take the minimum of these bounds. If there are at most two nontrivial events
separated by at most two rounds, and their local counts are exact, their product
is the exact full internal-trail probability. The selected-key three-round
candidate has this form and has probability
`22786271775649467675 / 295147905179352825856`, approximately 0.07720.

For the selected public key and skeleton input, the snapshots show:

| Rounds | -log2 heuristic score (not probability) | Proven upper bound on this internal candidate, approximately |
| --- | --- | --- |
| 2 | 1.898 | 2^-1.898; exact in JSON |
| 3 | 3.695 | 2^-3.695; exact in JSON |
| 4 | 13.231 | 2^-7.922 |
| 5 | 35.484 | 2^-17.737 |
| 6 | 56.919 | 2^-23.634 |
| 8 | 116.438 | 2^-32.810 |
| 12 | 245.127 | 2^-37.660 |
| 16 | 374.120 | 2^-37.803 |

Exact bounds are the fractions in JSON; rounded exponents above are for reading.
Best beam entries at different depths need not be prefixes of one another.
These bounds concern each **specified internal candidate** only, not all
characteristics, their endpoint differential, unknown keys or full-round security.
They remain valid if a candidate is actually impossible (probability zero).

### Held-out selected-key four-round improvement

The key is the same public key used in the previous selected-key experiment:

```text
80a557b4d8e5a404b1905568b0af068817ad63cabed2f9119950807984d97a61
input:       (0400260010000022, 8000000000000000)
old output:  (0400260010000022, 8220000008280808)
new output:  (0400260010000022, a26002600928080a)
```

The first scalar validation observed 3 new-endpoint hits in 16,384 pairs. A
separate, fixed-endpoint validation with a different generator/seed observed
**108 / 1,048,576**, versus **44 / 1,048,576** for the old endpoint on exactly
the same pairs. All 108 new hits followed the specified internal trail too;
this sample does not exclude other trails to that endpoint. Each was replayed
through the unmodified scalar cipher (216 encryptions). This is approximately
a 2.45-fold empirical improvement on that key and sample, not a proven ratio
of the true probabilities.

For the best three-round candidate under that key the small scalar validation
observed 1,257 / 16,384 pairs, consistent with its exact probability. No
five-round candidate hit appeared in the small validation. The high-round
candidate list contains no validated 16-round characteristic or attack.

## 7. Reproduction, costs and missing bounds

From the repository root, Python 3.11+:

```sh
# Standard library only: exhaustive model checks, constructed schedule cases,
# rigorous four-round parity intervals and bounded 1..16-round candidates.
python -m cryptanalysis.structural --output replay-structural.json

# Existing NumPy analysis dependency; held-out validation only, no search.
python -m pip install -r cryptanalysis/requirements.txt
python -m cryptanalysis.structural_followup --source replay-structural.json --output replay-structural-followup.json

# Original byte/target guards and conformance checks.
python -m unittest discover -v
python -m tools.vectors
```

Both drivers refuse to overwrite outputs. `--validate-only` on the first driver
runs the mathematical/model checks, reachability examples and parity intervals
without trail exploration. Parsed JSON is deterministic and can be compared
directly to the two committed result files. The old `cryptanalysis.reproduce`
command still reproduces its unchanged historical measurements.

Locally, CPython 3.14.7 on Windows: the standard-library driver took about
11 seconds, including roughly 2 seconds of model checks and 262,144 scalar
validation pairs across 16 fixed candidates; the NumPy follow-up took about
1 second. It uses 2^20 pairs per key for each four-round parity validation and
another 2^20 pairs for the selected endpoint comparison (6*2^20 block encryptions
in total, plus the 216 scalar replays). Follow-up batches hold 2^16 pairs; live
arrays occupy tens of MiB; the follow-up process's measured peak working set was
47.38 MiB (Windows process memory counters). Peak memory for the standard-library
driver was not successfully measured.
No GPU, external oracle, challenge-key query or expensive solver run was used.
These are local wall times, not CPU-independent performance claims.

What is still missing is specific:

1. Exact conditional joint counts across three or more active Feistel events,
   especially the five-round parity statistic, retaining the two base words and
   their nonlinear value relations. Per-round marginals do not provide them.
2. A search with complete candidate coverage and admissible suffix bounds, or
   a solver certificate excluding all higher-probability trails in a precisely
   defined domain. This beam search supplies neither.
3. Summation or bounded counting of all compatible trails for an endpoint
   differential. A single characteristic and a parity projection are different
   objects from that sum.
4. Schedule-aware analysis of joint weak-round conditions and actual attacks
   on 16 rounds, including cost and success probability. Single-round schedule
   surjectivity does not imply independently selectable successive pairs.
5. Full linear-mask/correlation searches, differential-linear continuation and
   key-recovery analysis. Low algebraic degree and reduced-round distinguishers
   alone do not establish their costs.

The strongest current conclusions are the affine classification and reachability
proofs, exact addition/dependency models, tight fixed-key four-round parity
bounds, and a validated improved selected-key four-round characteristic. They
do not justify a full-round security level or a quantified security margin.
