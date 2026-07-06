---
title: "Structure-aware fuzzing with AFL++ and SharpFuzz"
date: 2026-07-06T00:00:00.000Z
tags:
  - "dotnet"
  - "fuzzing"
  - "security"
  - "afl"
  - "structured fuzzing"
---

# Structure-aware fuzzing with AFL++ and SharpFuzz

With coverage-guided fuzzing we get better results than just feeding random data to our code and watching what crashes. But this approach can get stuck - at some point the coverage stops growing, no matter how long we run it. That is where structure-aware fuzzing, also called structured fuzzing, comes in.

## Why the byte-level fuzzer gets stuck

The coverage-guided fuzzer we used so far - AFL++ driving a .NET harness through my [Hornet](https://github.com/pawlos/hornet) framework - works on raw bytes. It takes an input, flips some bytes, adds or removes a few, and feeds the result to the harness. This works well for formats that are forgiving - where almost any bytes are good enough to get the parser to do some real work.

It works badly for formats that have a strict shape. Many formats start with a header that must look a certain way: a magic value, a length field, a table of offsets, a checksum, or some grammar the input has to follow. When the fuzzer flips a random byte, it usually breaks that shape. The parser looks at the input, sees it is invalid, and rejects it right away. The interesting code - the part that does the actual work - sits behind that check and is never reached.

So the fuzzer keeps knocking on the door but never gets inside. It can run millions of executions and still stay stuck at the same early check. The coverage stops growing.

## Bytes as a plan

The idea behind structure-aware fuzzing is simple. Instead of treating the fuzzer's bytes as the file we want to test, we treat them as a plan for building that file.

We read a few bytes to choose one thing, a few more bytes to choose another, and so on. For example: read one byte to pick an algorithm from a list, read two bytes to decide a length, take the next N bytes as the payload. Then we build a correct, well-formed file from those choices.

The fuzzer is still in charge. When it flips a "plan" byte, our builder produces a different file, and a different branch in the parser runs. But now every file we build has the right shape, so it always gets past the first check and reaches the real code.

This is not a new idea. libFuzzer has `FuzzedDataProvider`, Rust has the `arbitrary` crate. We do the same thing here, just for .NET.

The plan is read through a small helper - a cursor over the input bytes that hands out one value at a time. I call it `FuzzReader`:

```csharp
var r = new FuzzReader(input);
var alg = r.Pick(new[] { "HS256", "RS256", "none" }); // pick from a list
int count = r.Range(0, 16);                            // a bounded number
byte[] payload = r.Take(r.Int(256));                   // a chunk of bytes
```

One handy detail: when the input runs out, the reader returns zeros instead of throwing. So the harness never has to check the length before reading - it can always ask for the next value.

The rest of the harness does not change much. It is still an ordinary SharpFuzz harness reading from stdin. Only the first step is different: instead of passing the raw bytes to the library, we first turn them into a real file, and then pass that file to the library.

## Three ways to build the input

Depending on the format, building the input takes a slightly different shape. In practice there are three.

### Build from plan

Build the whole file from the plan. This fits formats that are fully described and cheap to create - tokens, wire formats, small binary structures.

A ZIP file is a good example. It is a chain of file headers, a central directory, and an end record, all tied together by offsets, sizes, and CRC checksums. Mutate a real ZIP at the byte level and almost any change breaks an offset or a checksum, so the reader gives up before it unpacks anything.

A structure-aware harness for it reads the plan - how many entries, each name, whether it is stored or compressed, its bytes - and then writes out a valid ZIP with correct offsets, sizes and CRCs. Every input now gets past the structural checks, so the code that parses the directory and decompresses the entries actually runs.

### Splice and fix up

Some formats are big and full of internal links that are annoying to build from scratch - fonts, archives, executables, media files. For these it is easier to start from a real file and change only parts of it.

We keep a known-good file as a template. Each round we let the fuzzer rewrite a few inner parts, and then we write the container back out with all the offsets, lengths and alignment fixed up. The container stays valid, so it always passes the outer check, but the inner data is now arbitrary - so the parsers for those parts get hit with data they would normally never see.

Fonts are a good fit for this. A TrueType/OpenType file starts with a table directory. We keep a real font's directory, replace the contents of a few tables with fuzzer data, and rebuild a valid file. The parsers for the individual tables (cmap, glyf, name and so on) then get exercised directly.

### Round trip

Some gates cannot be passed at all by mutating bytes. If a format is signed or encrypted, no amount of clever byte-picking will produce a valid signature or a valid authentication tag. The input will always fail the check and stop at "authentication failed".

The only way through is to let the harness make genuinely valid inputs, using keys it controls itself. We encode with a fixed key, then decode. The decode side now succeeds, which opens up everything that sits behind the check.

Signed and encrypted tokens like JWT and JWE are a good example. One mode forges tokens from the plan - good enough to reach the parsing and algorithm-dispatch code, but the forged ciphertext still fails the authentication check. A second mode encodes a token with its own keys and then decodes it. Now the decrypt succeeds, and code that only runs after a successful decrypt - like decompressing the payload - finally runs too.

## When it helps, and when it does not

Structure-aware fuzzing is not a free win. Whether it pays off depends on why the byte-level fuzzer was stuck in the first place.

- **Structural gate with a big parser behind it** - the best case. Offset tables, length fields, checksums and grammars are exactly the kind of thing a plan can satisfy by construction. If there is a large parser behind the gate, coverage grows a lot.
- **Cryptographic gate** - limited. You cannot mutate past a signature or a MAC. Structured inputs still stop at "authentication failed" unless the harness holds the keys and uses the round-trip trick.
- **Small target** - small win. If the library does not have much code to begin with, even full coverage is not a big number.

So the targets to pick are the ones with a strict structural gate and a lot of code behind it.

## A few things to keep in mind

- **You only find what you allow.** A builder that always writes a valid table directory will never find a bug in the directory parser itself, because it never sends a broken one. So keep the plain byte-level harness running too. The two are not a replacement for each other - they look for different things. It is worth running both side by side for exactly this reason.
- **Watch out for silent limits.** If the builder caps a length, a count, or a recursion depth to keep things fast, write it down somewhere. Otherwise a whole class of inputs is quietly out of scope and you might think you tested it.
- **Speed is not the goal, coverage per input is.** Structured inputs often cost more per execution - real compression, real crypto, bigger files. Fewer executions per second is fine if each one reaches deeper code.

## Wrapping up

In the [first post](20260308-fuzzing-dotnet-libraries.md) I listed structured fuzzing as one of the things I wanted to try next. This is that. The change is small in code - only the first step of the harness is different, turning the fuzzer's bytes into a real file instead of feeding them in raw - but it makes a big difference for formats with a strict shape. When the byte-level fuzzer is stuck at the front door, this is how we get it inside.