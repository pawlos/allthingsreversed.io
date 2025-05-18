---
title: "GynvaelEN - Mission 11 - Solution"
date: 2017-08-04T18:38:20.000Z
tags:
  - "gynvael"
  - "mission"
  - "solution"
feature_image: "content/images/2017/08/Zrzut-ekranu-2017-08-04-o-20.26.43.webp"
---

# GynvaelEN - Mission 11 - Solution

If you don't know Gynvael - check his [channel](https://www.youtube.com/gynvaelen) where he shows some RE/hacking stuff. After each video he posts some small challenge for solving by viewers. In this post I'll show how to solve [mission 11](https://www.youtube.com/watch?v=s5gOW-N9AAo).

In this [task](http://gynvael.vexillium.org/ext/c12192e97a9872d274ee4db57de34e835b3eacd0_mission011.txt) we're given a file that is the ["firmware"](goo.gl/axsAHt). When we open the file it is immediately know that it's a python byte code. If you don't know it - it's quite simple and actually very descriptive.

If you apply the opcodes definition to the given firmware you will start reconstructing the original function that was written in python.

It's not hard at all as all the information is given and not obfuscated at all.

So for example the lines:
[code]
    0 LOAD_CONST               1
    3 LOAD_ATTR                0
    6 LOAD_CONST               2
    9 CALL_FUNCTION            1

[/code]

can be written in python as `"4e5d4e92865a4e495a86494b5a5d49525261865f5758534d4a89".decode('hex')`. If we follow that for the rest of the file we are able to reconstruct the original function as:
[code]
    def check_password(s):
        good = "4e5d4e92865a4e495a86494b5a5d49525261865f5758534d4a89".decode('hex')
        if len(s) != len(good):
            return False

        result = []

        for cs,cg in zip(s,good):
            cs = ord(cs)
            cs -= 89
            cs &= 255
            cs ^= 115
            cs ^= 50
            result.append(cs==ord(cg))

        return all(result)
[/code]

And if we want to find out the password we need to create a reverse function.
[code]
    def check_password(s):
        good = "4e5d4e92865a4e495a86494b5a5d49525261865f5758534d4a89".decode('hex')
        if len(s) != len(good):
            return False

        result = []

        for cs,cg in zip(s,good):
            cs = ord(cs)
            cs = cs - 89
            cs &= 255
            cs ^= 115
            cs ^= 50
            result.append(cs==ord(cg))

        return all(result)

    def reverse_password():
        good = "4e5d4e92865a4e495a86494b5a5d49525261865f5758534d4a89".decode('hex')
        result = ""
        for c in good:
            ch = chr(((((ord(c) ^ 50) ^ 115) & 255) + 89) & 255)
            result += ch

        print result
        return result


    print check_password(reverse_password())

[/code]

If we run this, we will get: `huh, that actually worked!` which is the mission password.
