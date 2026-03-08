---
title: "N1CTF - n1vm writeup"
date: 2025-11-02T00:00:00.000Z
tags:
  - "n1ctf"
  - "reverse-engineering"
  - "ghidra"
  - "ida"
  - "virtual machine"
  - "z3"
---

## Introduction

`n1vm` was one of the four reverse engineering challenges in the N1CTF 2025. As a challenge file we are given `problem.exe` that we can load up to our favorite disassembler.

## VM analysis

The main program logic starts in `FUN_140001360` where some values are pushed onto the stack. This includes our inputs. This is de facto our VM initialization routine and execution starts here. The flow of the code is obfuscated in such a way that the code is split in chunks and next one is reached by using the chain of opcodes in the following form:

```asm
 lea R14, [next_chunk]
 push R14
 ret
```

Sometimes, if a chunk contains a conditional check, there is a conditional jump to another chunk that may occur before the end of the current chunk.

As mentioned, chunks do contain logic for the VM (passed in `R8`) and proceed to next chunks using the same pattern of `lea, push, ret`.

Following the flow of the code over a couple of chunks, we can see that the code is calculating two sums. First is stored at `VM[8]` (`sum1`) and the second one at `VM[0x10]` (`sum2`). Each of the sums is increased by the value from the table based on the index of the bit 1 in the value we've provided. `sum1` is constructed from values at `140005840` and `sum2` from values at `140005040`.

```
    140005040 [0] 35Eh, 60h, 203h, 73h,
    ...

    140005840 [0] 2F0h, 328h, 21Bh, 392h,
    ...
```

So, for example, if we provide a value of 6 (`0b110`), the `sum1` will be `0x328 + 0x21B = 0x543`, and `sum2` will be `0x60 + 0x203 = 0x263`. We iterate over 64 bits, shifting the value right by one on each iteration.

For completeness, the bit test is done at `0x140001CBD` and the right shift is in the chunk starting at `0x14000162F`.

```asm
140001cbd 4d 8b 58 18                         MOV          R11,qword ptr [R8 + param_3->field24_0x18]
140001cc1 49 f7 c3 01 00 00 00                TEST         R11,0x1
140001cc8 9c                                  PUSHFQ
140001cc9 41 5b                               POP          R11
140001ccb 4d 89 98 80 00 00 00                MOV          qword ptr [R8 + param_3->field128_0x80],R11
```

```asm
14000162f 49 c7 c3 81 03 00 00                MOV          R11,0x381
140001636 4c 23 dd                            AND          R11,RBP
140001639 4d 33 ce                            XOR          R9,R14
14000163c 4d 8b 48 18                         MOV          R9,qword ptr [R8 + param_3->field24_0x18]
140001640 4d 23 f3                            AND          R14,R11
140001643 49 83 ee 50                         SUB          R14,0x50
140001647 48 81 c5 24 01 00 00                ADD          RBP,0x124
14000164e 49 d1 e9                            SHR          R9,0x1       // <---- here
140001651 4d 03 db                            ADD          R11,R11
140001654 4d 0b f1                            OR           R14,R9
140001657 4c 8b f5                            MOV          R14,RBP
14000165a 4d 89 48 18                         MOV          qword ptr [R8 + param_3->field24_0x18],R9

```

To mimic this in python we could write it like this:
```python
def calc(v, num):
    sum_1 = 0
    sum_2 = 0    
    for bit in range(64):
        if v % 2 == 1:
            sum_1 += some_data_256_elems[bit+num*64]
            sum_2 += some_other_data[bit+num*64]
        v = v >> 1        
    return sum_1, sum_2
```

> The `num` parameter controls which part of the tables is used (indexes 0-63, 64-127, etc.) depending which number we process.

During this loop, there's one interesting check being done at `140001884`. `sum1` is compared with `0x1770` and if the value is greater than that, then we stop the calculation and with few chunks of code more we exit the VM calculation.

And after we are done with the first value, we continue with the next one. An important note here is that we keep the already-calculated sums.

The chunks that represent this loop for subsequent numbers are repeated in the binary, but the logic is the same.

After dealing with all four numbers there's another check that determines if we solve this challenge or not. Value at `VM[0x10]` (so `sum2`) is checked if it's equal to `0x7B82`. And if that's the case we will exit from VM with a value of `1` to indicate success.

```asm                             
1400016c8 4d 8b 58 10                         MOV          R11,qword ptr [R8 + 0x10]
1400016cc 49 81 fb 82 7b 00 00                CMP          R11,0x7b82
1400016d3 9c                                  PUSHFQ
1400016d4 41 5b                               POP          R11
1400016d6 4d 89 98 80 00 00 00                MOV          qword ptr [R8 + 0x80],R11
```

So to solve this challenge we need to find 4 numbers for which the calculation that VM does will yield a value of `0x7b82` for `sum2` while keeping the `sum1` below `0x1770`.

My first attempt was to solve it with Z3, but it didn't produce a solution in a reasonable time. ChatGPT suggested using a Mixed-Integer Linear Programming (MILP) solver.

```python
#!/usr/bin/env python3
from pulp import LpProblem, LpVariable, lpSum, LpBinary, LpMinimize, PULP_CBC_CMD

A = [int(x, 16) for x in """35e, 60, 203, 73, 23e, 19f, 2f9, 79, 3a6, 26a, 348, 3b6, 45, 286, fe, 2b1,
231, 1a0, 22d, 1f7, 37c, 16e, 3e1, 2ab, 22, 19b, 5a, 6, 191, 52, 383, 98, 8e, 1f1, 19c, 3d, 215,
11, 338, 61, 88, 22a, 115, 222, 224, 1c1, 2, 2fc, 1ab, 3c5, cf, 3bd, 37a, 1ef, 1da, 2e8, dd, 198,
20a, 205, 81, 2b3, 2bd, 233, 173, 2c3, 1de, 140, 144, 18c, f4, 32f, d8, 1e5, 4c, 341, 27f, 33, 211,
18f, 2c6, 382, 8a, 2ef, 2e1, ab, 29d, de, e1, 31a, 390, 3de, 1ca, 368, 276, 234, 132, 2b6, 10d, 80,
3c2, a4, 3da, 3b0, 21e, 379, 78, 21a, 3cd, 34b, 384, 342, 204, f0, 19e, 11c, d9, 2ae, 3cc, 1e7, 74,
2c1, 87, 3bb, 2f, 369, 20b, 7, 372, 114, 30c, 189, 2b9, 18b, 39a, 23b, 127, 24, 57, 261, 3e7, 259,
2d5, 39e, 1a3, 3c3, 2fa, 13d, b1, 3e5, 27e, 21, 2e2, 3b1, 334, 305, 10b, 3a4, a1, 17c, 27d, 251,
187, f7, 37b, 346, 1d1, 1a1, 180, 2d6, 13e, 330, 2d4, 9, 3cb, 170, b9, 298, 6e, a7, 1fe, 2de, 25d,
34a, 9e, 175, 93, 3ce, 30e, 1c2, 2e3, 12a, 2d, 2f2, 2e9, 1a8, 13c, 3c9, 8d, 36e, 27c, 26e, 337,
393, 280, 26f, eb, 387, 121, 26b, 183, 16f, 65, 16a, 92, 6a, 36f, 14e, 1fc, ae, 169, 31f, 18e, d4,
295, 99, 14b, 109, 134, a0, ed, 1ea, 2d9, 111, 333, 263, 2e6, 188, 55, 2f8, 117, 1db, 1af, e7, 296,
2a7, 2f1, 18, 154, 5d, 17e, da, 2a9, fc, cd, 289,""".split(',') if x.strip()]
B = [int(x, 16) for x in """2f0, 328, 21b, 392, ba, 371, 4e, 99, 61, 380, e9, 1f3, 33c, 18, 20e, 33, 28, aa, 158, 188,
381, 331, 2e, 40, 1e4, 11, 1ed, 1e1, 14f, 204, 24c, 1df, 32b, 1cf, 271, 2ad, 25f, bf, fe, 306, 11a,
19a, 1b0, 399, 33f, f1, 2bb, fa, 3a4, 385, 6b, 164, 2f6, 7f, 51, 223, 173, 12b, 3ad, 86, 106, 27d,
390, 201, 1ab, 1b7, 3c9, 303, 25a, 2b1, 2a0, 288, 142, b0, 1f5, 72, 3e0, 37f, 3c4, 285, 35f, 293,
2d4, 2a8, 15, f6, 3b6, 34b, 171, 2c3, 27b, 28d, 38c, 137, 3b0, 5e, 329, 265, 11c, 9d, 2de, 24, f3,
34f, 246, 266, 133, 3a, 8e, 273, 279, 33e, 9c, 2f8, 107, 1af, 222, 1a3, 323, 2ff, 234, 2af, f, 1fa,
3d7, 120, 344, 3c8, 149, 25d, 36d, 1a, 160, 221, 5b, 75, 197, 275, 1b9, 31e, 2bc, 34c, 143, 3d0, 302,
103, 30f, 378, 32e, 1bb, 2ee, 2e6, 1c6, b6, 280, 348, 2fd, 3b3, 3a1, 1cc, 352, 128, 38b, 155, 354,
1c3, 1e8, 242, 244, 139, 30c, 1d6, 3bd, 12, b2, 23c, 1b8, 2fc, 281, 1d5, 36e, 77, 5f, 3da, 17e, 5c,
3b8, 2f4, c0, ab, b7, 3ca, 335, 2e0, 9f, 30a, 1a8, 16f, 39b, 25c, 1b, 105, fb, 393, 257, 224, 109,
cb, 3ba, 264, a3, 30d, 114, 3e7, eb, c5, 9a, 1ad, 2c1, 4c, 94, 2ce, 210, 330, 3ce, 1c0, 8, 26a, 6c,
2ae, 1, 156, 2a2, 29c, 1c1, 1d0, 388, 20f, 11f, 364, 389, 68, 58, 11e, 163, 373, 132, 296, 368, 45,
111, 5d, 231, 168, 1ec, 1a7,""".split(',') if x.strip()]

TARGET_A = 0x7b82
MAX_B = 0x1770

model = LpProblem("subset", LpMinimize)

x = [LpVariable(f"x{i}", cat=LpBinary) for i in range(256)]

# Constraints
model += lpSum(A[i] * x[i] for i in range(256)) == TARGET_A
model += lpSum(B[i] * x[i] for i in range(256)) <= MAX_B

solver = PULP_CBC_CMD(msg=False)
status = model.solve(solver)

selected = [i for i in range(256) if x[i].value() > 0.5]
print("Selected indices:", selected)
print("A-sum:", sum(A[i] for i in selected))
print("B-sum:", sum(B[i] for i in selected))

masks = [0, 0, 0, 0]
for i in selected:
    masks[i // 64] |= 1 << (i % 64)
for j, m in enumerate(masks):
    print(f"mask[{j}] = {m} (hex {hex(m)})")

```

Running the script returns these four 64-bit values: `603623362480153936 2594381663086578176 5935814677652177097 1689210654328068`; providing them to the application yields the flag: `n1ctf{2c61982082d1af5052664054030285cd}`.

## Conclusion

The challenge revolved around understanding the inner workings of a small custom virtual machine that performed bitwise accumulation over lookup tables. Once the logic was reconstructed, it became clear that the problem could be expressed as a set of linear constraints — a perfect fit for an MILP solver. While Z3 struggled with the combinatorial search space, the linear formulation solved it cleanly and produced valid inputs that passed the VM's verification, revealing the flag.