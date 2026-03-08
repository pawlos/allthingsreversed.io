---
title: "A 29-Year-Old Bug in Quake II - Hunting a 64-bit Porting Issue in ref_soft"
date: 2026-03-08T00:00:00.000Z
tags:
  - "quake2"
  - "debugging"
  - "reverse-engineering"
  - "x86_64"
  - "bug-hunting"
---

# A 29-Year-Old Bug in Quake II

I've been working on [potatOS](https://github.com/pawlos/bug-free-potato) - a hobby 64-bit OS kernel that boots on QEMU. One of the recent milestones was getting Quake II running on it, using id Software's original GPL source code compiled for x86_64 with the software renderer (`ref_soft`). The game worked surprisingly well - until I walked into a specific area and the whole thing crashed.

## The crash

The crash was consistent and reproducible. Every time I entered a particular area of the map, the OS killed the Q2 task with a page fault:

```
[PAGE FAULT] cr2=0x7 errcode=0x7 RIP=0x480eca RSP=0x3fff8750
[PAGE FAULT] rbp=0x4 rbx=0x5
[PAGE FAULT] rdi=0x511 rsi=0x2ba2bd rdx=0x40000000 rcx=0x2ba2bd
[PAGE FAULT] r8=0xffffe6e9 r9=0x8c r12=0x3fff9598
[PAGE FAULT] User-mode fault — killing task
[SCHEDULER] Task 2 exiting with code 139
```

CR2=0x7 - that's a near-null pointer dereference. The error code 0x7 means present + write + user mode. Something is writing to address 0x7 from user space. Let's find out what.

## Disassembly at the crash site

RIP=0x480eca. Let's look at what's there:

```
$ objdump -d dist/userspace/quake2.elf --start-address=0x480da0 --stop-address=0x480ef0
```

The crash lands inside `R_PolygonScanLeftEdge`, a function in Q2's software renderer that fills in horizontal span data for polygon edges:

```asm
R_PolygonScanLeftEdge:
  ...
  480dcd: mov    r12, [rip+0x9501bc]     ; dd0f90 <s_polygon_spans>
  ...
  480e60: cvttss2si r9d, xmm0           ; r9d = itop (starting row)
  480e71: cvttss2si edi, xmm1           ; edi = ibottom (ending row)
  ...
  480ebc: mov    rdx, r12               ; rdx = s_polygon_spans (base pointer)
  480ebf: mov    eax, r9d               ; eax = itop
  ; --- inner loop: fill one span per scan line ---
  480ec8: mov    esi, ecx
  480eca: mov    [rdx+4], eax           ; <-- CRASH: write to rdx+4
  480ecd: add    eax, 1
  480ed0: add    ecx, r8d
  480ed3: sar    esi, 0x10
  480ed6: add    rdx, 0x18              ; rdx += sizeof(espan_t)
  480eda: mov    [rdx-0x18], esi
  480edd: cmp    edi, eax
  480edf: jne    480ec8
```

The loop iterates from `itop` (r9) to `ibottom` (edi), writing span entries. Each `espan_t` is 0x18 = 24 bytes on 64-bit (3 ints + a pointer). Now look at the register values from the crash dump:

- **r9 = 0x8c = 140** - the starting scan line (`itop`)
- **edi = 0x511 = 1297** - the ending scan line (`ibottom`)

The screen resolution is 320x240. A scan line of 1297 makes no sense on a 240-pixel-tall screen. These are projected screen-space vertex coordinates that should have been clipped to the viewport. Something went very wrong during vertex projection.

## Tracing the source

The function `R_PolygonScanLeftEdge` is called from `R_DrawPoly` (in `ref_soft/r_poly.c`), which is in turn called from `R_ClipAndDrawPoly`. The latter clips polygon vertices to the view frustum in world space, then projects them to screen coordinates:

```c
// ref_soft/r_poly.c, R_ClipAndDrawPoly()

// clip to the frustum in worldspace
nump = r_polydesc.nump;
for (i=0 ; i<4 ; i++)
{
    nump = R_ClipPolyFace (nump, &view_clipplanes[i]);
    if (nump < 3) return;
}

// transform vertices into viewspace and project
pv = &r_clip_verts[clip_current][0][0];

for (i=0 ; i<nump ; i++)
{
    VectorSubtract (pv, r_origin, local);
    TransformVector (local, transformed);

    if (transformed[2] < NEAR_CLIP)
        transformed[2] = NEAR_CLIP;

    pout = &outverts[i];
    pout->zi = 1.0 / transformed[2];

    pout->s = pv[3];
    pout->t = pv[4];

    scale = xscale * pout->zi;
    pout->u = (xcenter + scale * transformed[0]);

    scale = yscale * pout->zi;
    pout->v = (ycenter - scale * transformed[1]);

    pv += sizeof (vec5_t) / sizeof (pv);   // <--- !!!!
}
```

There it is. Line 991. Do you see it?

```c
pv += sizeof (vec5_t) / sizeof (pv);
```

`pv` is a `float *`. `vec5_t` is an array of 5 floats (20 bytes). The intent is to advance `pv` by 5 floats to the next vertex. Let's evaluate:

| Platform | `sizeof(vec5_t)` | `sizeof(pv)` | Result |
|----------|------------------|--------------|--------|
| **32-bit** | 20 | 4 | **5** (correct) |
| **64-bit** | 20 | 8 | **2** (wrong!) |

On 32-bit, `sizeof(float *)` happens to equal `sizeof(float)` - both are 4 bytes. The division gives 20/4 = 5, and the pointer advances correctly to the next vertex. On 64-bit, `sizeof(float *)` is 8, so 20/8 = 2 (integer division). The pointer advances by only 2 floats instead of 5, reading overlapping vertex data on each subsequent iteration.

The programmer meant to write `sizeof(*pv)` (the size of what the pointer points to - a float, 4 bytes) but wrote `sizeof(pv)` (the size of the pointer itself). This is a textbook 64-bit porting bug.

## Why only that area?

`R_ClipAndDrawPoly` is the rendering path for **translucent surfaces** - water, glass, and alpha-blended textures. Most of the map renders through a different code path (`R_DrawSolidClippedSubmodelPolygons` / `R_RenderFace`). The buggy projection only executes when the engine encounters a transparent surface.

With the pointer advancing by 2 instead of 5, vertex data gets scrambled. In most cases, the garbage coordinates either produce a degenerate polygon that gets rejected by the `ymin >= ymax` early-out in `R_DrawPoly`, or the projected coordinates happen to stay within bounds. But in that specific area - likely containing a water surface or glass with the right vertex layout - the corrupted projection produced v-coordinates of 140 to 1297 on a 240px screen. The span writer then iterated 1157 times, writing past the stack-allocated `espan_t spans[MAXHEIGHT+1]` array (1201 entries x 24 bytes) and past the mapped stack boundary at 0x40000000.

## The fix

One character:

```diff
-    pv += sizeof (vec5_t) / sizeof (pv);
+    pv += sizeof (vec5_t) / sizeof (*pv);
```

Every other similar line in the same file already uses the correct form:

```c
for (i=0 ; i<nump ; i++, instep += sizeof (vec5_t) / sizeof (float))
```

This one instance was simply inconsistent. On 32-bit x86, where Q2 was developed and shipped in 1997, the bug was invisible. `sizeof(float *) == sizeof(float) == 4`. It took compiling the original, unmodified ref_soft renderer for a 64-bit target to surface it - 29 years later.

## Checking if it's known

Searching online, I couldn't find this specific bug documented anywhere. [Fabien Sanglard's excellent Quake II code review](https://fabiensanglard.net/quake2/index.php) doesn't mention it - understandably, since it analyzes the 32-bit codebase where the bug doesn't manifest. The [Yamagi Quake II](https://github.com/yquake2/yquake2) project - the main 64-bit clean Q2 source port - appears to have rewritten significant portions of the software renderer rather than patching individual issues like this. Their [issue #5](https://github.com/yquake2/yquake2/issues/5) ("quake2 crashes going underwater") describes what is very likely the same root cause, though the issue thread doesn't identify the specific line.

Modern Q2 source ports almost universally use OpenGL or Vulkan renderers, so nobody runs `ref_soft` on 64-bit anymore. The original software renderer has been effectively abandoned, and this bug has been silently waiting in `r_poly.c` line 991 since December 1997.

## Takeaway

`sizeof(pointer)` vs `sizeof(*pointer)` is a classic 64-bit porting pitfall. On ILP32 platforms (where int, long, and pointers are all 32-bit), many `sizeof` expressions involving pointers accidentally produce correct results. Move to LP64 (64-bit pointers, 32-bit int) and they silently break.

If you're ever porting C code from 32-bit to 64-bit, grep for `sizeof` applied to pointer variables - especially in pointer arithmetic expressions. The compiler won't warn you. The code will compile cleanly. And it might even work most of the time, crashing only when you walk into the wrong room.
