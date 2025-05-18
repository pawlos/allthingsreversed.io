---
title: "Automating ghidra"
date: 2020-05-08T18:34:49.000Z
tags:
  - "ghidra"
  - "script"
  - "scripting"
  - "python"
  - "automate"
feature_image: "content/images/2020/05/ghidra_scrpting.webp"
---

# Automating ghidra

Ghidra is an awesome RE tool that quickly took off after its initial launch in 2019. It can display not only the disassembly of our binary but also have a decompiler that allows us to see a bit higher level code. You can also extend it by using python or Java. Let's see how we can write a simple script that will automate few things for us.

* * *

In the last post I was showing how we need to create a memory mam blocks when we do an analysis of NES rom. It required few operations to get complete. Let's see if we can automate the process.

Let's gather some information what we would like to get from our script:

  * carve out the ROM data from the file (skipping the header) and map it to the address `0x8000`
  * create additional blocks of memory with correct names and sizes

Let's see what API Ghidra provides for us. The documentation is available at address <https://ghidra.re/ghidra_docs/api/>. The documentation provides information about Java API but scripts can be also written in Python. We will use the latter.

The first what we need to know when writing in python is that we have two 'global' objects available. First is `currentProgram` that allows us to access things and other objects related to our binary as well as `monitor` that is required to be passed to some methods to track their progress.

First, from the `currentProgram` we can get hold of `Memory`.
[code]
    memory = currentProgram.getMemory()

[/code]

Having the reference to memory object we need to perform our steps. First we will delete the existing block, so that we can create new ones.
[code]
    blk = memory.getBlock(toAddr(0x0000))
    memory.removeBlock(blk, monitor)

[/code]

To do that, we first need to get a reference to a block that contains address `0x0000` and later remove it from our memory to make room for new blocks that we will create in a moment.

Creating uninitialized blocks is easy. We need to call the specific method passing correct arguments. Since those are uninitialized blocks we don't need to worry about bytes that will fill the content of the block.
[code]
    memory.createUninitializedBlock("internal_ram",toAddr(0x0000),0x2000,False)
    memory.createUninitializedBlock("ppu_regs", toAddr(0x2000),8, False)
    memory.createUninitializedBlock("apu", toAddr(0x4000),0x18, False)

[/code]

So the first argument is the block's name, following by the address at which the block starts. Next we have its length and as the last argument we pass `False` to indicate that it's not an overlay block.

Creating a block that will be back-up by data is just a bit more challenging. We need to pass the bytes. How do we get them? They are already in one block before we just deleted it. So let's extract them before we delete the block.
[code]
    fb = memory.getAllFileBytes()

[/code]

Now we can create the last block.
[code]
    memory.createInitializedBlock("rom", toAddr(0x8000), fb[0], 16, 0x8000, False)

[/code]

The arguments we are passing from first are: name, mapped address, file bytes, offset from the beginning of the file that we are mapping, length and lastly if this is again an overlay or not.

And that's almost all. We will have our blocks ready, but the we won't see our disassembly. We just need do start the process again. And we do it by calling `disassemble` providing the starting address.
[code]
    disassemble(toAddr(0x8000))

[/code]

The full, short script:
[code]
    memory = currentProgram.getMemory()
    fb = memory.getAllFileBytes()
    blk = memory.getBlock(toAddr(0x0000))
    memory.removeBlock(blk, monitor)

    memory.createUninitializedBlock("internal_ram",toAddr(0x0000),0x2000,False)
    memory.createUninitializedBlock("ppu_regs", toAddr(0x2000),8, False)
    memory.createUninitializedBlock("apu", toAddr(0x4000),0x18, False)
    memory.createInitializedBlock("rom", toAddr(0x8000), fb[0], 16, 0x8000, False)
    disassemble(toAddr(0x8000))

[/code]

Have fun.
