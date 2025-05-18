---
title: "Bitcoins for Flags"
date: 2022-03-12T20:07:31.000Z
tags:
  - "1337up"
  - "intigriti"
  - "reverse-engineering"
  - "reversing"
feature_image: "content/images/2022/03/top-1.webp"
---

# Bitcoins for Flags

> BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP BIP

> 🔗 Download link: [BitcoinsForFlags.zip](https://downloads.ctf.intigriti.io/1337UPLIVECTF2022-894ff411-aff8-453c-87b1-20ea939a7b6c/bitcoinsforflags/ba6f3ebd-4f22-49a9-872c-df3c7375e9a7/BitcoinsForFlags.zip)
> 🚩 Flag format: `CTF{}`
> ✍️ Created by Ferib Hellscream

`File` command gives us the info that we will be dealing with PE Windows executable.

> ❯ file BitcoinsForFlags.exe
> BitcoinsForFlags.exe: PE32+ executable (console) x86-64, for MS Windows

Running it (in the Sandbox) will ask for the passphrase:

> Please enter passphrase:

Let's open this file in Ghidra. After the initial analysis, we can navigate to `entry` and from there to `main` located at `0x1300015f0`. Decompiled code appears to be correct, but if we check closely the disassembly, we can notice some of the jumps are in the middle of the instruction. That might cause our disassembly to be completely off.
[code]
               LAB_14000167a                  XREF[1] 140001669 (j)
     14000167a 85 c0      TEST          EAX,EAX
     14000167c 75 08      JNZ           LAB_140001684+2
     14000167e 48 83      ADD           RSI,0x2
               c6 02
     140001682 31 f6      XOR           ESI,ESI
                  LAB_140001684+2                XREF[0, 14000167c (j)
     140001684 e8 18      CALL          SUB_1603e96a1
               80 3e 20
     140001689 75 e5      JNZ           LAB_140001670
     14000168b c6 06 5f   MOV           byte ptr [RSI],0x5f

[/code]

Let's use `c` to clear the opcodes and then rebuild at the correct offsets with the `d` key. Much better.
[code]
               LAB_14000167a                  XREF[1] 140001669 (j)
     14000167a 85 c0      TEST          EAX,EAX
     14000167c 75 08      JNZ           LAB_140001686
     14000167e 48 83      db[8]
               c6 02
               31 f6
                  LAB_140001686                  XREF[1] 14000167c (j)
     140001686 80 3e 20   CMP           byte ptr [RSI],0x20
     140001689 75 e5      JNZ           LAB_140001670
     14000168b c6 06 5f   MOV           byte ptr [RSI],0x5f
     14000168e 48 83      ADD           RSI,0x1
               c6 01

[/code]

After the cleaning up we can identify the binary's algorithm as follows:

  1. Read user input
  2. Scan char by char and if it's a space, replace with '_' (`0x5f`)
  3. For each group's chars (divided by '_') compute the following equation

[code]
    result = 0x811c9dc5
    for ch in group:
      result *= 0x1000193
      result ^= ch

[/code]

And the final result for each grup is compared with 15 values stored in the binary
[code]
     final
     140005040 a6 06      ddw           CF7F06A6h
               7f cf
     140005044 2a e2      ddw           B900E22Ah
               00 b9
     140005048 16 5d      ddw           14885D16h
               88 14
     14000504c 33 2d      ddw           1F882D33h
               88 1f

[/code]

From that information, we can deduce that the passphrase should be 15 words separated by space. Let's get back to the hashing algorithms. With CTF's challenges and such algorithms there's a high chance that it's not an original work but rather a known one. We can check if it's a known one by searching for the constants used in the code - here the values `0x11c9dc5` and `0x1000193`.

When we do that we can find out that the algorithm is [FNV hash](https://en.wikipedia.org/wiki/Fowler–Noll–Vo_hash_function). The simplicity of it is also good for replicating the code in python and trying to brute some easy values.
[code]
    def compute_and_check(s):
        edi = 0x811c9dc5
        for c in s:
    	    edi = ((edi * 0x1000193) & 0xFFFFFFFF) ^ ord(c)

        if edi in cmps:
    	    print(f'Found for {"".join(s)} value {hex(edi)} - idx {cmps.index(edi)}.')

[/code]

The only thing worth mentioning in the python algorithm is that we need to limit ourselves to 32-bits. And with that we can start finding the values. The initial approach was to start with printable characters, but it was getting all the sensible hits for lowercase characters.

Some words could be found very quickly

> ❯ python3 solve.py
> [+] Start...
> Found for gas value 0x228cf0d8 - idx 8.
> Found for ice value 0x14885d16 - idx 2.
> Found for bean value 0x46f0b24b - idx 6.
> Found for dust value 0x8bfce4a9 - idx 7.
> Found for easy value 0x1f882d33 - idx 3.
> Found for dutch value 0x150ac109 - idx 5.
> Found for honey value 0xcf7f06a6 - idx 0.
> Found for noble value 0x16ec9e5f - idx 12.
> Found for onion value 0x97b54a7c - idx 9.
> Found for since value 0x25f1922d - idx 11.
> Found for thank value 0x2b93d70b - idx 14.
> Found for almost value 0xa6c1280b - idx 10.

Few didn't popup that easily, esp. for index 1, 4 and 13. We could keep running the algorithm for little longer and considering the word is not that long obtain it, but we could use one additional feature of this hash.

Since there's no salt added, values for each word could be pre-computed and stored for later retrieval. Those as lookup table (rainbow tables) and to obtain the missing ones we will use one. I've used https://md5hashing.net/hash/fnv132/
It will take some time but after that we can obtain the info that for hash `0xb900e22a` corresponding word is `number`, for `0x2248f1e4` is `abandon` and `0xf2a74904` is `lobster`. Having all the words we can put them into the binary and obtain the flag

> Please enter passphrase: honey number ice easy abandon dutch bean dust gas onion almost since noble lobster thank
> Your flag: CTF{honey_number_ice_easy_abandon_dutch_bean_dust_gas_onion_almost_since_noble_lobster_thank}
