---
title: "Fuzzing .NET Libraries with AFL++ and SharpFuzz"
date: 2026-03-08T00:00:00.000Z
tags:
  - "dotnet"
  - "fuzzing"
  - "security"
  - "afl"
---

# Fuzzing .NET Libraries with AFL++ and SharpFuzz

For the past few weeks I've been spending time fuzzing various .NET libraries - both popular NuGet packages and Base Class Library (BCL) components. The goal was to find bugs that could be triggered by malformed input: null reference exceptions, out-of-bounds accesses, infinite loops, memory exhaustion and similar issues that parsers and deserializers are prone to. In this post I'll describe the approach, tooling and methodology.

## Why fuzz .NET?

Fuzzing native code (C/C++) is well-established. Tools like AFL, libFuzzer and honggfuzz have found thousands of bugs in everything from image decoders to cryptographic libraries. But managed languages like C# are often overlooked - the reasoning being that memory safety removes the most dangerous bug classes. That's true for buffer overflows and use-after-free, but it doesn't protect against:

- **Denial of Service** via `OutOfMemoryException` or `StackOverflowException` - a crafted input causing unbounded allocation or recursion
- **Null dereferences** (`NullReferenceException`) in edge cases the developer didn't anticipate
- **Index out of bounds** (`IndexOutOfRangeException`) when parsing headers or offsets from untrusted data
- **Infinite loops** where the parser gets stuck and never returns
- **Logic bugs** where malformed input causes unexpected behavior

These are real issues, especially when the libraries in question process untrusted input from the network - think image uploads, email parsing, archive extraction, certificate validation.

## The toolchain

The setup revolves around two key tools:

### AFL++

[AFL++](https://github.com/AFLplusplus/AFLplusplus) is a coverage-guided fuzzer. It takes seed inputs (a corpus), mutates them and feeds them to the target program. When a mutation triggers new code paths (measured via coverage instrumentation), it keeps that input for further mutation. This evolutionary approach is remarkably effective at exploring deep parser states.

### SharpFuzz

[SharpFuzz](https://github.com/Metalnem/sharpfuzz) by Nemanja Mijailovic bridges the gap between AFL++ and .NET. It does two things:

1. **IL instrumentation** - rewrites .NET assemblies to insert coverage tracking that AFL++ understands
2. **Fork server protocol** - implements the AFL++ fork server so the fuzzer can efficiently spawn test cases without cold-starting the .NET runtime each time

The combination gives us proper coverage-guided fuzzing for managed code.

## Setting up a harness

A fuzzing harness is a small program that reads input from stdin and feeds it to the target library. Here's the general pattern:

```csharp
using SharpFuzz;

Fuzzer.OutOfProcess.Run(stream =>
{
    try
    {
        MyLibrary.Parse(stream);
    }
    catch (ExpectedException)
    {
        // Parser correctly rejected malformed input - not a bug
    }
});
```

The `OutOfProcess` mode implements the AFL++ fork server protocol. Each fuzzing iteration gets a fresh process via `fork()`, so crashes in one iteration don't kill the fuzzer.

### Exception filtering - the key decision

The most important design choice is **what to catch and what to let crash**. A parser throwing `FormatException` on garbage input is working correctly. A parser throwing `NullReferenceException` is not.

I categorize exceptions into two buckets:

**Expected** (caught, not reported):
- `FormatException`, `ArgumentException`, `InvalidOperationException` - input validation doing its job
- `IOException`, `EndOfStreamException` - truncated input
- `OverflowException`, `NotSupportedException` - limits being hit
- Library-specific exceptions like `JsonReaderException`, `YamlException`, `ImageFormatException`

**Unexpected** (let through as crashes):
- `NullReferenceException` - something wasn't validated
- `IndexOutOfRangeException` - unchecked offset/index from input
- `OutOfMemoryException` - potential DoS via memory bomb
- `StackOverflowException` - unbounded recursion
- `AccessViolationException` - something really wrong
- `DivideByZeroException` - unchecked arithmetic from input data

A shared helper wraps this logic so all harnesses are consistent.

### Exercising multiple code paths

For libraries with multiple entry points, I try to cover as many as possible in a single harness. For example, an archive library harness might try ZIP, GZip, BZip2 and TAR parsing on the same input - each in its own try/catch. An image library harness might decode, then re-encode, then try different pixel formats. The more code paths the fuzzer can reach, the more bugs it can find.

## The instrumentation pipeline

Before fuzzing, the target DLLs need to be prepared:

1. **Publish** the harness as a framework-dependent deployment
2. **Strip ReadyToRun (R2R)** native code - .NET ships pre-compiled native code alongside IL for faster startup, but SharpFuzz needs the pure IL to instrument. This is done using Mono.Cecil to rewrite the assemblies, or for tricky composite assemblies, an ildasm/ilasm roundtrip
3. **Instrument** with SharpFuzz's CLI tool - this inserts the coverage tracking into the IL

For BCL targets (like `System.Text.Json` or `System.IO.Compression`), the process requires building the harness as self-contained so the framework DLLs are local and can be instrumented.

## Running the fuzzer

With everything instrumented, launching AFL++ looks like:

```bash
afl-fuzz -i corpus/ -o findings/ -t 5000 -- \
    dotnet publish/Harness.MyLibrary/Harness.MyLibrary.dll
```

Key settings:
- **Timeout** (`-t 5000`) - 5 seconds per input, enough for .NET JIT warmup
- **Dictionaries** - AFL++ supports token dictionaries that improve mutation quality. For an image parser, this might include magic bytes, chunk type names and format-specific keywords
- **`DOTNET_TieredCompilation=0`** - reduces JIT non-determinism that confuses coverage tracking
- **`DOTNET_ReadyToRun=0`** - ensures instrumented IL is used instead of pre-compiled native code

## Triaging crashes

AFL++ saves crash-triggering inputs to `findings/crashes/`. But raw crashes need triaging:

1. **Replay** each crash input to confirm it's reproducible
2. **Capture stack traces** to understand the root cause
3. **Deduplicate** - many crash inputs trigger the same underlying bug. Group by exception type + crash location
4. **Minimize** with `afl-tmin` - find the smallest input that still triggers the crash. This helps when creating bug reports

I automated this with a triage script that replays crashes, captures the exception info and groups them.

## What I targeted

I focused on libraries that process untrusted input - parsers and deserializers are the natural attack surface:

**NuGet packages:**
- Image processing (ImageSharp)
- HTML parsing (AngleSharp)
- Email/MIME parsing (MimeKit)
- Archive handling (SharpZipLib)
- Cryptography (BouncyCastle)
- Serialization formats (MessagePack, CsvHelper, YamlDotNet, Markdig, Newtonsoft.Json)
- Image metadata (MetadataExtractor)

**BCL components:**
- `System.Text.Json`
- `System.IO.Compression`
- `System.Formats.Tar`
- `System.Formats.Cbor`
- `System.Security.Cryptography.Cose`
- `System.Security.Cryptography.Pkcs`
- `System.Configuration.ConfigurationManager`

## Results

Without going into specifics (some issues are still being reported and fixed), I can say that fuzzing found real bugs across several libraries. The types of issues discovered include:

- **Null reference exceptions** in edge cases of format parsing
- **Division by zero** when header fields contained unexpected values
- **Index out of range** when offset calculations weren't properly validated
- **Infinite loops** where malformed input caused the parser to spin forever
- **Excessive memory allocation** triggered by crafted size fields

Some libraries proved more robust than others. Well-fuzzed libraries like `System.Text.Json` and `Newtonsoft.Json` yielded nothing - a testament to the testing already done on them. Others, particularly those dealing with complex binary formats, had more surface area to explore.

The bugs found have been or are being reported to the respective maintainers. Some have already been fixed in newer releases.

## Lessons learned

**Corpus quality matters.** Starting with valid, minimal seed files for each format dramatically improves the fuzzer's effectiveness. A 100-byte valid JPEG gives the fuzzer a much better starting point than random bytes.

**Dictionaries help.** Providing format-specific tokens (magic bytes, field names, encoding markers) helps AFL++ make smarter mutations. Writing a dictionary for each target format is worth the effort.

**Exception filtering is an art.** Too strict and you miss bugs. Too loose and you drown in false positives. I iterated on the filters as I understood each library's expected behavior better.

**BCL fuzzing is harder but valuable.** The self-contained build + R2R stripping pipeline adds friction, but bugs in BCL components affect every .NET application.

**SharpZipLib is a graveyard.** Some libraries are effectively unmaintained. Finding 20+ crashes in such a library raises the question of whether to report them at all or just recommend users migrate to alternatives.

## What's next

There's always more to fuzz. More libraries, deeper harnesses (covering more API surface), and longer fuzzing campaigns. I'm also looking into:

- **Structure-aware fuzzing** - generating inputs that respect format grammars rather than pure byte-level mutation
- **Differential fuzzing** - comparing outputs of multiple libraries that handle the same format
- **Continuous fuzzing** - running campaigns against new library releases automatically

If you maintain a .NET library that processes untrusted input - consider fuzzing it. The toolchain is mature and the barrier to entry is lower than you might think.
