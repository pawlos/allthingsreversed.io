---
title: "Automating Ghidra - part 3"
date: 2021-04-10T19:37:25.000Z
tags:
  - "ghidra"
  - "script"
  - "scripting"
  - "automate"
  - "automating"
  - "crackme"
  - "armageddon"
feature_image: "content/images/2021/04/ghidra_scrpting.webp"
---

# Automating Ghidra - part 3

In the third installment of this series (if you haven't read/seen here's - [part 1](20200508-scripting-ghidra.md) & [part 2](20200707-automating-ghidra-part-2.md)) we will be reconstructing program flow. This is useful for tasks such as [Towel's armageddon](https://crackmes.one/crackme/5edb0b8533c5d449d91ae73b).

* * *

Note: If you prefer watching, have a look at my [YouTube channel](https://www.youtube.com/channel/UCCt61WyhWeHvLVMbgbpvvYw).

[Watch on YouTube](https://www.youtube.com/watch?v=-lJGEb6mOB0)

The difficulty of this crackme is that it contains (as noted in the description) slight obfuscation. It has a form of program flow obfuscation that looks like the following:
[code]
                  LAB_00014a0c                   XREF[1] 00014a04 (j)
       014a0c 00 48      stmdb  sp!,{r11 lr}
              2d e9
       014a10 00 00      b      LAB_00014a18
              00 ea
       014a14 07         ??     07h
       014a15 43         ??     43h    C
       014a16 94         ??     94h
       014a17 2b         ??     2Bh    +
                  LAB_00014a18                   XREF[1] 00014a10 (j)
       014a18 04 b0      add    r11,sp,#0x4
              8d e2
       014a1c 00 00      b      LAB_00014a24
              00 ea
       014a20 d9         ??     D9h
       014a21 5a         ??     5Ah    Z
       014a22 05         ??     05h
       014a23 ec         ??     ECh
                  LAB_00014a24                   XREF[1] 00014a1c (j)
       014a24 58 d0      sub    sp,sp,#0x58
              4d e2
       014a28 00 00      b      LAB_00014a30
              00 ea
       014a2c 1b         ??     1Bh
       014a2d f5         ??     F5h
       014a2e 8e         ??     8Eh
       014a2f f4         ??     F4h
                  LAB_00014a30                   XREF[1] 00014a28 (j)
       014a30 f8 08      ldr    r0=>s_---------------_-=UMDCTF_2019=-_-_0  = 000153d4
              9f e5                                                        = "--------
       014a34 00 00      b      LAB_00014a3c
              00 ea
       014a38 7e         ??     7Eh    ~
       014a39 05         ??     05h
       014a3a 8a         ??     8Ah
       014a3b 5f         ??     5Fh    _
                  LAB_00014a3c                   XREF[1] 00014a34 (j)
       014a3c 50 ee      bl     puts                              int puts(ch
          ff eb
       014a40 00 00      b      LAB_00014a48
          00 ea
       014a44 a2         ??     A2h
       014a45 d5         ??     D5h
       014a46 66         ??     66h    f
       014a47 3a         ??     3Ah    :

[/code]

The program listing is a mess. Only one valid instruction followed by a jump and few bytes of garbage makes the analysis a bit tougher. Disassembly is looking correct, but if we would like to check the disassembly we have a problem.

Here comes Ghidra's scripting API. We could use the API to extract instructions, skip those unconditional jumps and reconstruct the code.

To do that we can use `currentProgram.getListing().getInstructionAt(addr)` to check if the instruction is an unconditional jump, we can get the Flow type information
[code]
    t = instruction.getFlowType()
    if t == RefType.UNCONDITIONAL_JUMP:

[/code]

There's one more tricky part - in order to get an instruction string we need to do the following
[code]
    codeUnitFormat = CodeUnitFormat(CodeUnitFormatOptions(CodeUnitFormatOptions.ShowBlockName.ALWAYS,CodeUnitFormatOptions.ShowNamespace.ALWAYS,"",True,True,True,True,True,True,True))

    codeUnitFormat.getRepresentationString(instruction)

[/code]

Without that we would be missing some important stuff like references, and string.

The full script.
[code]
    #armageddon
    from ghidra.program.model.listing import CodeUnitFormat, CodeUnitFormatOptions
    from ghidra.program.model.symbol import RefType
    codeUnitFormat = CodeUnitFormat(CodeUnitFormatOptions(CodeUnitFormatOptions.ShowBlockName.ALWAYS,CodeUnitFormatOptions.ShowNamespace.ALWAYS,"",True,True,True,True,True,True,True))
    addr = toAddr('')

    limiter = 0
    limit = 50
    instruction = currentProgram.getListing().getInstructionAt(addr)
    while True:
    	t = instruction.getFlowType()
    	if t == RefType.UNCONDITIONAL_JUMP:
    		dest_addr = toAddr(int(str(instruction)[2:],16))
    		sym = currentProgram.symbolTable.getPrimarySymbol(dest_addr)
    		if 'LAB_' in str(sym):
    			addr = dest_addr
    			instruction = currentProgram.getListing().getInstructionAt(addr)
    			continue
    	print(str(instruction.address) +': '+codeUnitFormat.getRepresentationString(instruction))
    	instruction = instruction.getNext()
    	limiter += 1
    	if limiter > limit:
    		break

[/code]

Running it will give us listing without those jumps
[code]
    000104f4: b .text:check_flag_1
    000104fc: stmdb sp!,{r11 lr}
    00010508: add r11,sp,#0x4
    00010514: sub sp,sp,#0x8
    00010520: str flag,[r11,#local_c+0x4]
    0001052c: ldr r3,[r11,#local_c+0x4]
    00010538: add r3,r3,#0x15
    00010544: ldrb r3,[r3,#0x0]
    00010550: cpy r2,r3
    0001055c: ldr r3,[r11,#local_c+0x4]
    00010568: add r3,r3,#0x27
    00010574: ldrb r3,[r3,#0x0]
    00010580: mul r3,r3,r2
    0001058c: ldr r2,[r11,#local_c+0x4]
    00010598: add r2,r2,#0x1
    000105a4: ldrb r2,[r2,#0x0]
    000105b0: mul r3,r2,r3
    000105bc: ldr r2,[r11,#local_c+0x4]
    000105c8: add r2,r2,#0x11
    000105d4: ldrb r2,[r2,#0x0]
    000105e0: add r2,r3,r2
    000105ec: ldr r3,[r11,#local_c+0x4]
    000105f8: add r3,r3,#0x1e
    00010604: ldrb r3,[r3,#0x0]
    00010610: cpy r1,r3
    0001061c: ldr r3,[r11,#local_c+0x4]
    00010628: add r3,r3,#0x13
    00010634: ldrb r3,[r3,#0x0]
    00010640: mul r3,r3,r1
    0001064c: add r3,r2,r3
    00010658: ldr r2,[.text:DAT_000106d0]
    00010664: cmp r3,r2
    00010670: beq .text:LAB_000106a4
    0001067c: ldr flag=>.rodata:s__[!]_Code_did_not_validate!_:(_000153b4,[.text:PTR_s__[!]_Code_did_not_validate!_:(_000106d4]
    00010688: bl .plt:puts
    ....

[/code]

Now we can analyze it without problems.
