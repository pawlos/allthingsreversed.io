---
title: "N1CTF - Whimsical_Ideas_Happy_SShheeeepp Writeup"
date: 2025-11-08T00:00:00.000Z
tags:
  - "n1ctf"
  - "reverse-engineering"
  - "ghidra"
  - "ida"
  - "driver"
  - "ads"
  - "ntfs"
---

## Introduction

`Whimsical_Ideas_Happy_SShheeeepp` was one of the four reverse engineering challenges in the N1CTF 2025. As a challenge file we are given an `attachment.rar` that contains the following files:

```
- README.txt
- IronGate.sys
- SheepVillage.txt
- Init.exe
```

The README.txt gives an intro to the challenge:

> For the safety of your computer, please solve the problems in a virtual machine!!!
> Already tested on Windows 10 22H2. (Versions of Win10 from 2004 (10.0.19041) onwards should all be able to run.)

> Welcome to the Green Green Grassland.
> Catch all the sheep hiding in the sheep village.
> Start the game after running "Init.exe" as an administrator.
> Use this directory as the working directory, and in the command line (such as cmd.exe or PowerShell), enter ".\catch_[key].txt" to catch the sheep.
> Flag is "n1ctf{[happy sshheeeepp key][beauty sshheeeepp key][lazy sshheeeepp key][boil sshheeeepp key][warm sshheeeepp key][slow sshheeeepp key]}".

> GL! HF! 

We can start by loading the `IronGate.sys` - there's probably the logic we should focus on. By analyzing the `DriverEntry` and surrounding methods we can spot two things: first - there are some debug messages in this driver. Methods are containing `DbgPrint` calls that we can use that to peek inside driver processing data. Secondly it's a minifilter driver - it uses `FltRegisterFilter`.

```c
__int64 __fastcall sub_140006000(PDRIVER_OBJECT Driver)
{
  NTSTATUS started; // ebx

  if ( (dword_140003028 & 1) != 0 )
    DbgPrint("IronGate!DriverEntry: Entered\n");
  started = FltRegisterFilter(Driver, &Registration, &Filter);
  if ( started >= 0 )
  {
    started = FltStartFiltering(Filter);
    if ( started < 0 )
      FltUnregisterFilter(Filter);
  }
  return (unsigned int)started;
}
```

From the `Registration` object we can access the `OperationRegistration` field and there we can get access to `pre_operation` and `post_operation` methods. They are located respectively at `0x140001000` and `0x140001260`. Before we start digging into the code lets start to install and run the driver.

## Installing the driver

We could use native windows tool to install and start/stop the driver but the attached `Init.exe` program will do that for us.

## Driver logic

The `pre_operation` starts with logging information that the action has happened and then compare the file that the driver is processing does start with `catch_`. Next, it extracts 4 bytes after that prefix and converts them from unicode to ascii. Those 4 bytes are treated as base-64 input and are decoded to actual bytes. We can follow all this in the log as debug messages are put across all those methods.

```
pre!ViEn: IrpMj=00.00 IRP_MJ_CREATE Name="\Device\HarddiskVolume2\Users\flare\Desktop\Whimsical_Ideas_Happy_SShheeeepp\attachment\catch_+VqB.txt"
input_ = 4200710056002B
input = 4271562B
decode => 815AF9
```

The decoded value is now transformed with the following routing (translated to python):

```python
def transform(v):
    for _ in range(10):
        v = ((v >> 17) ^ ((v << 7) & 0xFFFFFF)) & 0xFFFFFF
    return v
```

And the value after transformation is being printed with `DbgPrint("func => %X\n",v);` so again we can check if what we are calculating matches the driver.

Computed value is now converted to base64 and appended to `SheepVillage.txt:` so it's treated as an alternate data stream indicator. 
Let's check if that file does have some ADS attached to it.

```
streams SheepVillage.txt

streams v1.60 - Reveal NTFS alternate streams.
Copyright (C) 2005-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

C:\Users\flare\Desktop\Whimsical_Ideas_Happy_SShheeeepp\attachment\SheepVillage.txt:
            :576O:$DATA 30
            :5oeS:$DATA 28
            :5oWi:$DATA 28
            :5pqW:$DATA 28
            :5rK4:$DATA 28
            :5Zac:$DATA 29
```

We can check the content:

```
Get-Content -Path ".\SheepVillage.txt" -Stream 576O
You caught beauty sshheeeeppp!
```

So the first stream contains the `beauty sheep` and the rest some other. So our goal here is to find such input, that after transformation and converted to base64 would give us the ADS names. When we will have those we can construct the flag as described in the task description.

The input space is not that big so we can brute-force all the possibilities with the following script:

```python
def transform(v):
    for _ in range(10):
        v = ((v >> 17) ^ ((v << 7) & 0xFFFFFF)) & 0xFFFFFF
    return v

def decode(chars4_bytes):
    return int.from_bytes(base64.b64decode(chars4_bytes), 'little')

def encode(v):
    return base64.b64encode(struct.pack('<I', v))

def produced_suffix_for_candidate(candidate_4):
    decode = decode(candidate_4)
    func = transform(decode)
    suffix = encode(func)[:4]
    return suffix
    
for i0 in range(64):
  b0 = B64_BYTES[i0]
  for i1 in range(64):
      b1 = B64_BYTES[i1]
      for i2 in range(64):
          b2 = B64_BYTES[i2]                
          for i3 in range(64):
              b3 = B64_BYTES[i3]
              cand = bytes([b0,b1,b2,b3])
              suf = produced_suffix_for_candidate(cand)
              if target in suf: 
                  return cand.decode('ascii')
```

Putting this into the script we can find all the values:

> ❯ python3 find_exact_preimage.py 576O
> candidate: nvs6
> ❯ python3 find_exact_preimage.py 5oeS
> candidate: mh9K
> ❯ python3 find_exact_preimage.py 5oWi
> candidate: mheK
> ❯ python3 find_exact_preimage.py 5pqW
> candidate: mmta
> ❯ python3 find_exact_preimage.py 5rK4
> candidate: msvi
> ❯ python3 find_exact_preimage.py 5Zac
> candidate: llty

and from the suffixes generate the final flag: `n1ctf{lltynvs6mh9KmsvimmtamheK}`.

## Final notes

This challenge combined Windows kernel reverse engineering, base64 decoding, and bit-level transformations to recover hidden alternate data streams. By analyzing the driver’s filter callbacks and reproducing its 24-bit transformation in Python, we could brute-force valid inputs that generated each ADS key.