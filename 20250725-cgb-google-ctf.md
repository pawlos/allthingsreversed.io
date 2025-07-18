---
title: "cgb - Google CTF 2025 — Challenge Writeups & Analysis"
date: 2025-07-25T00:00:00.000Z
tags:
  - "google"
  - "reverse-engineering"
  - "ghidra"
  - "gba"
---

# cgb

ℹ️ I did not solve this task during the CTF.

*cgb* was one of the reversing challenge from Google CTF 2025. It was solved by 23 teams and during the CTF I did manged to get part of the solution but not the final flag. Having a bit more time after the CTF I did attempt to solve it and here's a writeup.

The task description reads:

> A game I found in a developer's drawer, it looks like an unfinished game about a character jumping rocks?  

and we are given an attachment that contains the following files

```
├── README.md
├── hash
│   └── gbcolor.xml
└── roms
    ├── gbcolor
    │   ├── gbc_boot.1
    │   └── gbc_boot.2
    └── gctf
        └── gctf.gb
```

Checking the `README.md` we can see an extra information about how we can run the game.


> I don't have a console with me, but you can emulate it with [MAME](https://www.mamedev.org/):  
>  
> ```sh  
> $ /usr/games/mame -hashpath hash -window -rp roms gbcolor gctf  
>  ```

Lets boot up the game and see what it is about.

When starting the game we can see a main screen
![](content/images/2025/07/cgb_start_screen.jpg)

and after pressing start we can start it

![](content/images/2025/07/cgb_game.jpg)

but after a while the game stops showing a garbage on screen.

![](content/images/2025/07/cgb_endstate.jpg)

Lets see what is inside it using Ghidra.