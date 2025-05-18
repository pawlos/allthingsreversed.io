---
title: "Handling self-modifying​ code with radare2"
date: 2018-07-05T04:58:29.000Z
tags:
  - "radre2"
  - "self-modifying-code"
  - "smc"
feature_image: "content/images/2018/07/Screen-Shot-2018-07-05-at-06.36.11.webp"
---

# Handling self-modifying​ code with radare2

This is a post that explains a little bit in details what was shown in the two videos that could be watched on my YT channel. If you haven't seen them and are not yet confused enough about I recommend go check them out.

[Watch on YouTube](https://www.youtube.com/watch?v=BBWtpBZVJvQ) [Watch on YouTube](https://www.youtube.com/watch?v=8GsiQWVlyLg)

As they might not explain the topic enough well, let's start from the beginning.

## A bit of theory

Starting with some theory. What is a self-modifying code? Well, the name says it all - it is a code that is modifying itself. It might be in a form of in-memory decryption or modification of one or more values in memory.

It might look something like this:
[code]
        lea rax, [0x00201039]
        lea rdx, [0x00201064]
    0x0020102e:
        xor byte [rax], 0x55
        inc rax
        cmp rax, rdx
        jne 0x0020102e
    0x00201039:
        sbb eax, 0x555850d8
        push rbp
        push rbp
        invalid
        push rbp
        <some more gibberish>
    0x00201064:

[/code]

or just innocent
[code]
        lea rax, [0x0020104d]
        add byte [rax], 0x61
        <some code>
    0x0020104c: mov al, 0x66

[/code]

Why it's done like that? To make the code and/or data impossible to reason. In our binary, they would like garbage. The sole reason is to make the analysis more time-consuming. I won't write impossible as this only slows down the reversing process.

## How to deal with SMC in radare2

Radare2 has a way to deal with such code and continue our static analysis. So how this could be achieved? Well, with the use of 'write with operation' command - `wo`?

If we check the current r2 output for `wo` we will get the following:

> radare2 2.7.0-git 18775 @ darwin-x86-64 git.2.6.9-31-ga566e7af9
>  commit: a566e7af99c4b5a0833615f16f0841aab2a342bb build: 2018-07-05__05:47:32
[code]
    [0x00000000]> wo?
    |Usage: wo[asmdxoArl24] [hexpairs] @ addr[!bsize]
    | wo[24aAdlmorwx]               without hexpair values, clipboard is used
    | wo2 [val]                     2=  2 byte endian swap
    | wo4 [val]                     4=  4 byte endian swap
    | woa [val]                     +=  addition (f.ex: woa 0102)
    | woA [val]                     &=  and
    | wod [val]                     /=  divide
    | woD[algo] [key] [IV]          decrypt current block with given algo and key
    | woe [from to] [step] [wsz=1]  ..  create sequence
    | woE [algo] [key] [IV]         encrypt current block with given algo and key
    | wol [val]                     <<= shift left
    | wom [val]                     *=  multiply
    | woo [val]                     |=  or
    | wop[DO] [arg]                 De Bruijn Patterns
    | wor [val]                     >>= shift right
    | woR                           random bytes (alias for 'wr $b')
    | wos [val]                     -=  substraction
    | wow [val]                     ==  write looped value (alias for 'wb')
    | wox [val]                     ^=  xor  (f.ex: wox 0x90)

[/code]

As r2 changes every day, your output might be different but I do hope when you are reading this the command still do exists ;)

So we see a bunch of 'write' command that can apply a different operation to the bytes that are being read & write. Nice. And this is our solution to SMC. How? By issuing the same operation that the code would do to the memory block but just with `radare2` commands.

So in the example above that would be in two parts.

First:
[code]
    ?vi 0x00201064 - 0x0x00201039
    43

[/code]

to calculate the length of the block that we need to modify and after that, the operation itself:
[code]
    wox 55 @ 0x00201039!43

[/code]

Splitting it a bit to explain a bit more:

`wox` \- write with xor operation
`55` \- the key to the xoring, every byte will be xored with that value
`@ 0x00201039` \- the position where to start the operation
`!43` \- how many bytes we need to update

And voilà. You got yourself a new binary that has the gibberish decoded with radare2.

And now it looks a bit more readable:
[code]
    0x00201039 lea rax, [0x0020104d]
    0x00201040 add byte [rax], 0x61
    0x00201043 lea rcx, [0x0020106f]
    0x0020104a xor edx, edx
    0x0020104c mov al, 0x66
    <more code>

[/code]

One bit of a note here. Since the operation is done on the binary itself - remember to make a copy before you do this in case something got mixed up. The second thing is that by default r2 opens the file in read-only mode. You need to reopen it in read-write and one can do that by issuing `oo+` command.

For the other example with just simple byte modification with adding will suffice.
[code]
    woa 61 @ 0x0020104d!1

[/code]

and a true constant reveals itself!
[code]
    0x0020104c mov al, 0xc7 ; before it was 0x66

[/code]

Double voilà!

As it could be sine from the `wo?` output there's some are multiple operations that we can apply. And of course, we can issue one after another to simulate more complex algorithms i.e. xor with addition.

Hope now the SMC and how to deal with it in radare2. Have fun!
