---
title: "Debugging r2"
date: 2021-04-22T16:59:35.000Z
tags:
  - "r2"
  - "radare2"
  - "debugging"
  - "dbg"
  - "tips"
  - "tricks"
feature_image: "content/images/2021/04/r2_top.png"
---

# Debugging r2

This will be a short one.

If you ever need to debug Radare2, and after running it under `dbg` you can't get into the debugger after hitting `^C` as it should, remember that `r2` handles this shortcut and this won't work.

Instead use this:

> kill -SIGTRAP $(pidof r2)

This cause r2 to break and you will end up in `dbg` prompt.
