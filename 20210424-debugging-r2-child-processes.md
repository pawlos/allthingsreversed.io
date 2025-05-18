---
title: "Debugging r2 - child processes"
date: 2021-04-24T10:26:20.000Z
tags:
  - "r2"
  - "radare2"
  - "debugging"
feature_image: "content/images/2021/04/r2_top-1.png"
---

# Debugging r2 - child processes

If you ever want to debug `r2` while it is debugging another process (so basically debug while debug `r2 -d /bin/ls` or when using `ood`) remember about few important things.

Radare2 will create a new process so it is important to be sure if `gdb` is set to attach to a newly created process or keep being attached to the parent depending on the use case. It can be changed by setting `follow-fork-mode` variable to either `child` or `parent`.

By default it is set to `child` so it would seems to be correct, but if we would like to check what `r2` is doing after the process has been created and before it started execution it would need to be changed to `parent` and later to `child` again.

This was handy to know for checking why some payloads where not loaded correctly to provide an answer for [this](https://reverseengineering.stackexchange.com/questions/27355/radare2-does-not-reload-payload-correctly/27447#27447) Stack Overflow question.
