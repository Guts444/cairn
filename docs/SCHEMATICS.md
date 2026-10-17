# Cairn v0.1 schematics

Transcribed from the frozen [specification](SPEC.md) and
[`core.py`](../cairn/core.py). Every wire below carries **64 bits**, except the
256-bit master-key input and 128-bit block concatenations. `+` means addition
modulo 2^64; `XOR` is bitwise; `ROL n` rotates a 64-bit word left. Bit 0 is the
least significant bit. These are structural diagrams, not security arguments.

## One complete Feistel round

```mermaid
flowchart TD
    LI["L_i : 64 bits"] --> X["XOR : 64 bits"]
    RI["R_i : 64 bits"] --> F["F(R_i, u_i, v_i)"]
    K["u_i, v_i : two 64-bit subkeys"] --> F
    F --> X
    RI --> LO["L_(i+1) = R_i"]
    X --> RO["R_(i+1) = L_i XOR F(R_i, u_i, v_i)"]
```

Parse `BE64(L_0) || BE64(R_0)`. Repeat for `i = 0..15`, then return
`BE64(L_16) || BE64(R_16)`: **no extra final swap and no whitening**.
Both output assignments use the old halves. Reduced variants use the prefix
of the same full schedule. Inverse round:
`(L_i,R_i) = (R_(i+1) XOR F(L_(i+1),u_i,v_i), L_(i+1))`.

## Round function, in implementation order

```mermaid
flowchart TD
    R["r : 64 bits"] --> A["ADD modulo 2^64"]
    U["u : 64 bits"] --> A
    A --> X["x = r + u"]
    X --> J["XOR of three 64-bit inputs"]
    X --> R13["ROL 13"] --> J
    X --> R37["ROL 37"] --> J
    J --> Y["y = x XOR ROL(x,13) XOR ROL(x,37)"]
    Y --> B["ADD modulo 2^64"]
    V["v : 64 bits"] --> B
    B --> Z["z = y + v"]
    Z --> Q["XOR of three 64-bit inputs"]
    Z --> R17["ROL 17"] --> Q
    Z --> R41["ROL 41"] --> Q
    Q --> T["t = z XOR ROL(z,17) XOR ROL(z,41)"]
    T --> R29["ROL 29"] --> OUT["F(r,u,v) : 64 bits"]
```

The three branches of each XOR layer use the **same pre-layer word**; these
are not three sequential in-place XOR updates. Define `P = I XOR ROL13 XOR
ROL37` and `Q = I XOR ROL17 XOR ROL41`. Then `F = ROL29 o Q o A_v o P o A_u`,
where `A_k(x) = x + k (mod 2^64)`.

## Key schedule: one iteration, repeated 24 times

Capital letters below name intermediates, so the sequential dependencies and
final simultaneous reassignment are explicit.

```mermaid
flowchart TD
    KEY["Master key : 256 bits, big endian"] --> S["Parse a, b, c, d : four 64-bit words"]
    S --> LOOP["Iteration i = 0..23; input state a,b,c,d"]
    LOOP --> A["A = a + ROL(b,9) + C_i modulo 2^64"]
    CONST["G = 0x9E3779B97F4A7C15; C_i = (i+1)*G modulo 2^64"] --> A
    A --> C["C = c XOR ROL(A,23)"]
    LOOP --> C
    C --> D["D = d + ROL(C,31) modulo 2^64"]
    LOOP --> D
    D --> B["B = ROL(b XOR D,17)"]
    LOOP --> B
    A --> NEXT["Simultaneous new state: (a,b,c,d) = (B,C,D,A)"]
    B --> NEXT
    C --> NEXT
    D --> NEXT
    NEXT --> EMIT{"i >= 8?"}
    EMIT -->|"no: 8 warmup iterations, i=0..7"| CONT["Advance i; feed new state to next iteration"]
    EMIT -->|"yes: 16 emissions, i=8..23"| RK["round_key[i-8] = (a XOR c, b+d modulo 2^64) = (B XOR D, C+A)"]
    RK --> CONT
    CONT -->|"if i < 23"| LOOP
```

The emission uses the state **after** reassignment. All 24 iterations run even
when an experiment requests fewer than 16 rounds. Each emitted key is 128 bits;
the schedule state remains 256 bits. Constants are public, iteration-dependent
64-bit words, not additional key material.

## Source cross-check

| Diagram | Frozen implementation | Checks |
| --- | --- | --- |
| Feistel | `Cipher.encrypt_block` | Big-endian halves; one swap per round; XOR into old left; no final swap |
| Function | `round_function` | Add u, P, add v, Q, ROL29; all operations on 64 bits |
| Schedule | `expand_key` | ROL9/23/31/17; updated A/C/D dependencies; permute before emission; 8 warmups + 16 keys |

The research reproductions also check an independently written schedule step
and its inverse against all 16 emitted keys, and check both linear-layer
inverses on every basis vector. Frozen-byte conformance remains enforced by
`python -m unittest discover -v`.
