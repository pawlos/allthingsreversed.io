---
title: "Flare-On 8 - known"
date: 2021-11-02T21:27:47.000Z
tags:
  - "flare-on-8"
  - "flare-on"
  - "reverse-engineering"
  - "reversing"
  - "binary"
  - "ghidra"
feature_image: "content/images/2021/11/capa.webp"
---

# Flare-On 8 - known

> We need your help with a ransomware infection that tied up some of our critical files. Good luck.

With the second challenge, it's a bit step up in the difficulty. We are given an EXE with some files (different types; images images and text) that has been encrypted.

Opening file in Ghidra, we can see less than 10 methods. From `entry` we can identify `main` and check what it's doing.
[code]
    local_c = FindFirstFileA(s_*.encrypted_0040372c,(LPWIN32_FIND_DATAA)&local_194);
    if (local_c == (HANDLE)0xffffffff) {
      FUN_004010c0(s_FindFirstFile_0040371c);
    }
    while( true ) {
      do {
        local_14 = FUN_00401030((int)local_54,(int)local_194.cFileName);
        local_194.cAlternateFileName[local_14 + 6] = '\0';
        FUN_00401220(local_194.cFileName,local_54,param_1);
        local_8 += 1;
        BVar1 = FindNextFileA(local_c,(LPWIN32_FIND_DATAA)&local_194);
      } while (BVar1 != 0);
      DVar2 = GetLastError();
      if (DVar2 == 0x12) break;
      FUN_004010c0(s_FindNextFile_0040370c);
    }
    FUN_00401160(local_8);

[/code]

The core part is the following:

  * find files with `.encrypted` extension
  * prepares a new name, without `.encrypted` extension
  * call `FUN_00401220` with the new name, original name a argument passed to the binary

Cleaning up the above code, we can get the following, much readable version
[code]
    File = FindFirstFileA(s_*.encrypted_0040372c,(LPWIN32_FIND_DATAA)&local_194);
    if (hFile == (HANDLE)0xffffffff) {
      exit(s_FindFirstFile_0040371c);
    }
    while( true ) {
      do {
        fileNameLen = copy(fileName,local_194.cFileName);
        local_194.cAlternateFileName[fileNameLen + 6] = '\0';
        decrypt_files(local_194.cFileName,fileName,pass);
        cnt += 1;
        res = FindNextFileA(hFile,(LPWIN32_FIND_DATAA)&local_194);
      } while (res != 0);
      DVar1 = GetLastError();
      if (DVar1 == 0x12) break;
      exit(s_FindNextFile_0040370c);
    }
    print_stats(cnt);

[/code]

`decrypt_files` is the function we want to focus and check the code (again, after a clean up) we can see that the main routine is simple `decrypt` function written as follow
[code]
    void __cdecl decrypt(char *dst,char *src)

    {
      byte j;
      uint i;

      i = 0;
      while (j = (byte)i, (char)j < 8) {
        dst[i] = ((dst[i] ^ src[i]) << (j & 7) | (byte)(dst[i] ^ src[i]) >> 8 - (j & 7)) - j;
        i = (uint)(byte)(j + 1);
      }
      return;
    }

[/code]

The function works in chunks of 8 bytes and transforms them according the the above formula. This actually might be a bit confusing with the `shift`-s, and `or`-s, but if we would look at the assembly (which is sometimes better - see [https://allthingsreversed.io/dont-trust-the-decompilers/](20210517-dont-trust-the-decompilers.md)) it's clear that the routine is build from two simple opcodes: `xor`, `rol` and `sub`.

Simplifying, each character is processed in the following way:
[code]
    dst[j] = rol(inp[j] ^ key[j], j) - j # j goes from 0 to 7

[/code]

`Rol` (and `ror`) are not available in python but we can write then using simple lambda:
[code]
    ror = lambda val, r_bits, max_bits: \
        ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
        (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

    rol = lambda val, r_bits, max_bits: \
        (val << r_bits%max_bits) & (2**max_bits-1) | \
        ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

[/code]

To use them, we need to provide the additional information as 3rd parameter - size of the data - in this case - 8 bits).

Knowing the routine, there's still one problem - password for the decryption. It's being passed as an argument to this code and we don't know it, yet.

Let's focus on the encrypted files. We have, `cicero.txt.ecnrypted`, `commandovm.gif.encrypted`, `critical_data.txt.encrypted`, `flarevm.jpg.encrypted`, `lating_alphabeth.txt.encrypted` and `capa.png.encrypted`.

Some of those images, are known FlareVM images that we could find and extract password for the encryption. But we have a simpler sample. `latin_alphabeth.txt.encrypted`.

If we consider the file name to be telling the truth, we should have all the Latin letters inside this file. Let's see what we will get if we can reverse the routine and get the password (knowing the output and the input):
[code]
    def extract_key(dst, inp):
        key = [None]*len(inp)
        for j in range(8):
            key[j] = ror(inp[j] + j,j) ^ dst[j]
        return key

[/code]

If we pass our encrypted `latin_alphabeth.txt.encrypted` and potential input `"ABCDEFGHIJKLMNOPQRSTUVWXYZ"` we can retrieve the key: `No1Trust`. Having that, we can decode the rest of the files and obtain the flag: `(>0_0)> You_Have_Awakened_Me_Too_Soon_EXE@flare-on.com <(0_0<)`. Solved.
