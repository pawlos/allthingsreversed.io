---
title: "Corpus Delicti: Infinite Loops — NCalc case"
date: 2026-06-23T00:00:00.000Z
tags:
  - "ncalc"
  - "fuzzing"
  - "bugs"
  - "infinite loop"
  - "bug-hunting"
---

# Corpus Delicti

When people think about serious bugs they think C, C++. Buffer overflows. Memory corruption. The classics.
.NET is safe. Managed memory. Garbage collector. No raw pointers. But safe doesn't mean bug-free.
Infinite loops that hang your server. Stack overflows that kill your process. Parsers that allocate gigabytes for a 35-byte input. Not headline material — but real bugs, in real libraries, hiding in plain sight. Welcome to *Corpus Delicti*.

---

# Infinite loop in NCalc

The recent infinite loop finding in NCalc is an interesting one. At first glance it seems there's nothing wrong with it. But if we look closer we can find an issue. Let's examine the code:

```csharp
private static T CalculateFactorial<T>(T n) where T : INumber<T>
{
    if (n < T.Zero)
        throw new ArgumentOutOfRangeException(nameof(n));
    var one = T.One;
    var r = one;

    for (var i = one + one; i <= n; i++)
        r *= i;

    return r;
}
```

It's a generic method that gets executed for specific types via a public-facing method.

```csharp
public static object Factorial(object? result)
{
    return result switch
    {
        int v => CalculateFactorial(v),
        long v => CalculateFactorial(v),
        float v => CalculateFactorial(v),
        double v => CalculateFactorial(v),
        decimal v => CalculateFactorial(v),
        BigInteger v => CalculateFactorial(v),
        _ => throw new ArgumentException("Unsupported numeric type.", nameof(result)),
    };
}
```

Can you spot the bug already? No? Look again.

Since we control the `v` we can request it to spin for a very long time. What will happen if we request to calculate 99999999999999!? It will try to fulfill our request and do a lot of iterations. It's not yet an infinite loop — it will finish at some point but it will take some time. But what will happen if we do the same for 9223372036854775807!? 

The number might look familiar but it should click if I represent it as a hex number — 0x7FFFFFFFFFFFFFFF. It's the `long.MaxValue`. So let's see what will happen with our loop for that value:

1. We enter the method with `n` set to `0x7FFFFFFFFFFFFFFF`
2. `n` is not less than `T.Zero` so we don't exit with an exception.
3. We assign `T.one` to `one` and `r`.
4. We start our iterations: `i` ranging from 2 to `0x7FFFFFFFFFFFFFFF+1`.
5. But what will happen when `i` will be equal to `0x7FFFFFFFFFFFFFFF` and we add `1` to it?

It will be equal to `0x8000000000000000` but that's a `long.MinValue` so the exit condition that controls exiting the loop will not be met and it will continue to spin never reaching the end.

## It's not just the integers

It's tempting to file this under "signed integer overflow" and move on, but remember the same generic method is instantiated for `float` and `double` too. Those types never wrap around to a negative value, so the overflow story doesn't apply to them — and yet they hang just as well, for a different reason.

Floating point numbers only have so many bits of mantissa: 23 for `float`, 52 for `double`. Once a value grows past `2^24` (float) or `2^53` (double), the gap between two representable numbers becomes larger than `1`. At that point `i++` rounds straight back to `i` — adding `1` no longer changes anything:

```csharp
double i = 9_007_199_254_740_992; // 2^53
i == i + 1;                       // true!
```

So for a large enough `double` argument, `i` simply stops advancing. It never overflows, it never reaches `n`, and the `i <= n` condition stays true forever. Same hang, no wraparound in sight.

`decimal` and `BigInteger` round out the picture. `decimal` keeps growing until it throws an `OverflowException`, so it terminates (loudly) rather than looping. `BigInteger` has no overflow and no precision limit at all - it will happily keep multiplying ever-larger numbers, burning CPU and ballooning memory until something else gives out. Different failure modes, same root cause: nothing bounds `n`.

## Why it matters

A factorial helper hanging in isolation would be a curiosity. The reason this one earned an advisory is *where* it lives. NCalc is an expression evaluator — its whole job is to take a string, often from somewhere you don't control, and compute it. A web service that lets users plug in formulas, a rules engine, a reporting tool with a calculated-field box: all of these can end up feeding attacker-influenced text straight into NCalc.

That turns a one-line expression into a denial-of-service primitive. Evaluating something as innocent as

```
9223372036854775807!
```

is enough to peg a CPU core and never return. The thread handling that request is gone; send a handful in parallel and you can starve the whole thread pool. No memory corruption, no exploit chain, no crash dump to investigate - just a server that quietly stops responding. That's exactly the kind of unglamorous, easy-to-miss bug this series is about.

Solution? Clamp the maximum `n` that factorial can be calculated for, and do it *before* the loop rather than trusting the loop condition to stop. The bound is smaller than you might think. `double` tops out around `1.8 × 10^308`, and `170!` ≈ `7.26 × 10^306` is the largest factorial that still fits — `171!` ≈ `1.24 × 10^309` overflows straight to `+Infinity`. So past `170` you aren't computing anything useful anyway; the result can't be represented. A simple `if (n > 170) throw ...` guard kills the hang and loses nothing, since anything beyond that point was already garbage. (The exact cap depends on the type — `decimal` overflows far sooner — but `170` is the ceiling that matters for the floating-point cases.)

## References

- Advisory: [GHSA-3w5p-95mh-gq75](https://github.com/advisories/GHSA-3w5p-95mh-gq75)
- Package: [`NCalcSync` / `NCalc` on NuGet](https://www.nuget.org/packages/NCalcSync)
- Weakness: CWE-835 (Loop with Unreachable Exit Condition — "Infinite Loop")
- Impact: Denial of service via attacker-controlled expression
