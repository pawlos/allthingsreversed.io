---
title: "HITCON 2022 - Meow Way"
date: 2022-11-27T17:08:00.000Z
tags:
  - "hitcon"
  - "hitcon-2022"
  - "ctf"
  - "reverse-engineering"
  - "reversing"
feature_image: "content/images/2022/11/top-1.webp"
---

# HITCON 2022 - Meow Way

> Reverse-engineering like the meow way!

We are given a Windows 32-bit executable that we can load into Ghidra. In the initial peak into the `main`, we can see the following
[code]
      (*DAT_0040544c)(iVar3,iVar3 >> 0x1f,iVar3,iVar3 >> 0x1f,0xc4,0,&local_10,&local_10 >> 0x1f);
      iVar2 = iVar3 + 1;
      (*DAT_004053a8)(iVar2,iVar2 >> 0x1f,iVar2,iVar2 >> 0x1f,0x16,0,&local_10,&local_10 >> 0x1f);
      iVar2 = iVar3 + 2;
      (*DAT_004053b4)(iVar2,iVar2 >> 0x1f,iVar2,iVar2 >> 0x1f,0x8e,0,&local_10,&local_10 >> 0x1f);
      iVar2 = iVar3 + 3;
      (*DAT_004053f0)(iVar2,iVar2 >> 0x1f,iVar2,iVar2 >> 0x1f,0x77,0,&local_10,&local_10 >> 0x1f);
      iVar2 = iVar3 + 4;
      (*DAT_00405448)(iVar2,iVar2 >> 0x1f,iVar2,iVar2 >> 0x1f,5,0,&local_10,&local_10 >> 0x1f);
      iVar2 = iVar3 + 5;
      (*DAT_004053fc)(iVar2,iVar2 >> 0x1f,iVar2,iVar2 >> 0x1f,0xb9,0,&local_10,&local_10 >> 0x1f);
      iVar2 = iVar3 + 6;
      (*DAT_00405400)(iVar2,iVar2 >> 0x1f,iVar2,iVar2 >> 0x1f,0xd,0,&local_10,&local_10 >> 0x1f);
      iVar2 = iVar3 + 7;
      (*DAT_00405410)(iVar2,iVar2 >> 0x1f,iVar2,iVar2 >> 0x1f,0x6b,0,&local_10,&local_10 >> 0x1f);
      iVar2 = iVar3 + 8;
      (*DAT_004053f8)(iVar2,iVar2 >> 0x1f,iVar2,iVar2 >> 0x1f,0x24,0,&local_10,&local_10 >> 0x1f);
      iVar2 = iVar3 + 9;
      <continuing..>

[/code]

It looks cryptic, but after a quick look, those `DATA_00405XXX` are function pointers. After cleaning it a bit more we can obtain the following code
[code]
      flag = argv[1];
      (*ptrF1)(flag,flag >> 0x1f,flag,flag >> 0x1f,0xc4,0,&local_10,&local_10 >> 0x1f);
      pcVar2 = flag + 1;
      (*ptrF2)(pcVar2,pcVar2 >> 0x1f,pcVar2,pcVar2 >> 0x1f,0x16,0,&local_10,&local_10 >> 0x1f);
      pcVar2 = flag + 2;
      (*ptrF3)(pcVar2,pcVar2 >> 0x1f,pcVar2,pcVar2 >> 0x1f,0x8e,0,&local_10,&local_10 >> 0x1f);
      pcVar2 = flag + 3;
      (*ptrF4)(pcVar2,pcVar2 >> 0x1f,pcVar2,pcVar2 >> 0x1f,0x77,0,&local_10,&local_10 >> 0x1f);
      pcVar2 = flag + 4;
      (*ptrF5)(pcVar2,pcVar2 >> 0x1f,pcVar2,pcVar2 >> 0x1f,5,0,&local_10,&local_10 >> 0x1f);
      pcVar2 = flag + 5;
      (*ptrF6)(pcVar2,pcVar2 >> 0x1f,pcVar2,pcVar2 >> 0x1f,0xb9,0,&local_10,&local_10 >> 0x1f);
      pcVar2 = flag + 6;
      (*ptrF7)(pcVar2,pcVar2 >> 0x1f,pcVar2,pcVar2 >> 0x1f,0xd,0,&local_10,&local_10 >> 0x1f);
      pcVar2 = flag + 7;
      (*ptrF8)(pcVar2,pcVar2 >> 0x1f,pcVar2,pcVar2 >> 0x1f,0x6b,0,&local_10,&local_10 >> 0x1f);
      pcVar2 = flag + 8;
      (*ptrF9)(pcVar2,pcVar2 >> 0x1f,pcVar2,pcVar2 >> 0x1f,0x24,0,&local_10,&local_10 >> 0x1f);
      pcVar2 = flag + 9;
      <continuing..>

[/code]

We can see that each call is done for each character of the flag, and at the end we compare the output of those with a predefined byte buffer in the binary.

`iVar3 = memcmp(&::flag,argv[1],0x30);`

To find the flag, we need to analyze those functions under `ptrFXX`. Let's take a look at one of them (f8). We need to see the assembly as the decompilation yields an empty one (just return).
[code]
    undefined  __stdcall  f8(void )
            00403468 6a  33           PUSH       0x33
            0040346a e8  00  00       CALL       LAB_0040346f
                     00  00
    LAB_0040346f:
            0040346f 83  04  24  05    ADD        dword ptr [ESP],0x5
            00403473 cb              RETF

[/code]

The `retf` is suspicious here. And the whole `call` and `ADD dword ptr[esp]` action is weird too. What's happening here is the switch to execute 64-bit code and modification of the return pointer via `[esp]`, instructs to continue execution just after the `retf` opcode. Since the binary is 32-bit and this is Ghidra's mode of operation, if we decompiled the next few bytes, we would have them wrongly presented. Just for the sake of learning, let's see them:
[code]
    00403474 48              DEC        EAX
    00403475 31  c0          XOR        EAX ,EAX
    00403477 65  48          DEC        EAX
    00403479 8b  40  60      MOV        EAX ,dword ptr [EAX  + 0x60 ]=>DAT_0000005f
    0040347c 48              DEC        EAX
    0040347d 0f  b6  80      MOVZX      EAX ,byte ptr [EAX  + 0xbc ]
             bc  00  00  00
    00403484 67  8b  4c  24  MOV        ECX ,dword ptr [SI + 0x24 ]
    00403488 1c  83          SBB        AL,0x83
    0040348a e0  70          LOOPNZ     LAB_004034fa+2
    0040348c 67  89  01      MOV        dword ptr [BX + DI],EAX
    0040348f 85  c0          TEST       EAX ,EAX
    00403491 75  18          JNZ        LAB_004034ab
    00403493 67  8b  7c  24  MOV        EDI ,dword ptr [SI + 0x24 ]
    00403497 04  67          ADD        AL,0x67
    00403499 8b  74  24  0c  MOV        ESI ,dword ptr [ESP  + 0xc ]
    0040349d 67  8b  4c  24  MOV        ECX ,dword ptr [SI + 0x24 ]
    004034a1 14  67          ADC        AL,0x67
    004034a3 2a              ??         2Ah    *
    LAB_004034a4:
    004034a4 0e              PUSH       CS
    004034a5 80  f1  f7      XOR        CL,0xf7
    004034a8 67  88  0f      MOV        byte ptr [BX],CL
    LAB_004034ab:
    004034ab e8  00  00      CALL       LAB_004034b0
             00  00
    LAB_004034b0:
    004034b0 c7  44  24      MOV        dword ptr [ESP  + 0x4 ],0x23
             04  23  00
             00  00
    004034b8 83  04  24  0d  ADD        dword ptr [ESP ],0xd
    004034bc cb              RETF
    004034bd c3              RET

[/code]

It's looking weird, isn't it? Now, let's use Capstone to generate 64-bit assembly:
[code]
    xor     rax, rax
    mov     rax, qword ptr gs:[rax + 0x60]
    movzx   rax, byte ptr [rax + 0xbc]
    mov     ecx, dword ptr [esp + 0x1c]
    and     eax, 0x70
    mov     dword ptr [ecx], eax
    test    eax, eax
    jne     0x1037
    mov     edi, dword ptr [esp + 4]
    mov     esi, dword ptr [esp + 0xc]
    mov     ecx, dword ptr [esp + 0x14]
    sub     cl, byte ptr [esi]
    xor     cl, 0xf7
    mov     byte ptr [edi], cl
    call    0x103c
    mov     dword ptr [rsp + 4], 0x23
    retf
    ret

[/code]

It makes more sense now. If we checked all the other functions, they would have the same structure with different values used in the `xor` and the initial operation being either `sub` or `add`. We can work with that variety quite easily.

What we are still missing is what values are being passed and used. We can see the procedure references `[esp + 4]`, `[esp + 0xc]` and `[esp + 0x14]`. From the code, we can easily deduce the `[esp + 4]` and `[esp + 0xc]` are the destination and source buffers, respectively. But what is `[esp + 0x14]`? It's the fifth argument, and we can see from the call-site `(*ptrF8)(pcVar2,pcVar2 >> 0x1f,pcVar2,pcVar2 >> 0x1f,0x6b,0,&local_10,&local_10 >> 0x1f);` it's this magical constant value of `0x6b`. I think we have all the ingredients to cook up the final script.

From the binary, we can extract the final bytes, located at `0x405018`. Magic values are not separated by the same byte interval, but we can locate them by the marker bytes. If we encounter `\x6a\x68` or `\x6a\x6a` starting from offset `0x835` in the binary, the next byte is our magic value.

Functions are a bit trickier, but they can also be located by the marker bytes, `\x83\x04\x24\x05\xcb`. We could check the bytes but since I already had capstone in place, I've used textual representation to determine if we have `add` or `sub`. The last part is to extract `xor` value from the function, but it can also be done in a similar fashion. To calculate the original value, we can use the following formula:
[code]
     if 'add' in op:
        flag.append(((result[j] ^ secret) - calls[j]) & 0xff)
     if 'sub' in op:
        flag.append((calls[j] - (result[j] ^ secret) ) & 0xff)

[/code]

And that's all. Final script:
[code]
    from capstone import *

    result = bytes.fromhex('9650cf2ceb9baafb53ab73dd6c9edbbceeab23d616fdf1f0b975c328a2747de327d5955cf57675c98cfb420ebd51a298')
    calls = []
    data = open('meow_way.exe','rb').read()
    start = 0x835
    while True:

        if data[start] == 0x6a and (data[start+2] == 0x68 or data[start+2] == 0x6a):
            calls.append(data[start+3])
            if len(calls) == 0x2f:
                break

        start += 1

    j = 0
    flag = []
    start = 0
    functions = []
    while True:
        if data[start:start+5] == b'\x83\x04\x24\x05\xcb':
            functions.append(start+5)
            if len(functions) == 0x2f:
                break
        start += 1

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for addr in functions:
        CODE = data[addr:addr+0x44]
        opcodes = []
        for i in md.disasm(CODE,0x1000):
            opcodes.append(format("%s\t%s" %(i.mnemonic, i.op_str)))

        op = next(filter(lambda x: 'byte ptr [esi]' in x, opcodes), None)
        xor = next(filter(lambda x: 'xor\tcl' in x, opcodes), None)
        secret = int(xor.replace('xor\tcl, ',''),16)
        if 'add' in op:
            flag.append(((result[j] ^ secret) - calls[j]) & 0xff)
        if 'sub' in op:
            flag.append((calls[j] - (result[j] ^ secret) ) & 0xff)
        j += 1


    print(''.join([chr(x) for x in flag]))

[/code]

And the flag:

`hitcon{___7U5T_4_S1mpIE_xB6_M@G1C_4_mE0w_W@y___}`
