---
title: "GynvaelEN - Mission 12 - Solution"
date: 2017-08-05T07:08:56.000Z
tags:
  - "gynvael"
  - "mission"
  - "solution"
feature_image: "content/images/2017/08/Zrzut-ekranu-2017-08-05-o-08.44.37.webp"
---

# GynvaelEN - Mission 12 - Solution

In this [mission](http://gynvael.vexillium.org/ext/a5da6349803f65783958b51c3b9fd15c3c35c0d5_mission012.txt) we are given the data from the hardware logger.

On the first look we see some printable characters but nothing obvious.

To solve this we need to get some knowledge about
[scancodes](https://en.wikipedia.org/wiki/Scancode).

The article on Wiki gives some clue that we might be on a right track as it is mentioning the `F0` prefix that we see in the data:

`58 f0 58 1b f0 1b...`

but it lacks the scan codes (apart from few examples) so we need to search a bit more.

A few more searches and we find the [right table](http://www.computer-engineering.org/ps2keyboard/scancodes2.html).[1]

Since there are not so many keys used in the dumped data we can map them manually but when mapping only the first one we discovered that some special chars (like Caps Lock) are used. In order to get the correct casing for the password we will need to implement a bit more logic to handle that.

We need to handle Caps (press - `0x58` & release `0xF0 0x58`), Left Shift (press - `0x12` & release `0xF0 0x12`) and Right Shift (press - `0x59` & release `0xF0 0x59`) and change the casing accordingly.

Full solution (not very efficient) is here:
[code]
    #http://gynvael.vexillium.org/ext/a5da6349803f65783958b51c3b9fd15c3c35c0d5_mission012.txt
    codes = "58 f0 58 1b f0 1b 58 f0 58 44 f0 44 2d f0 2d 2d f0 2d 35 f0 35 41 f0 41 29 f0 29 59 43 f0 43 f0 59 29 f0 29 23 f0 23 44 f0 44 31 f0 31 52 f0 52 2c f0 2c 29 f0 29 1b f0 1b 4d f0 4d 24 f0 24 1c f0 1c 42 f0 42 29 f0 29 12 42 f0 42 f0 12 24 f0 24 35 f0 35 32 f0 32 44 f0 44 1c f0 1c 2d f0 2d 23 f0 23 49 f0 49".replace(" ","").decode('hex')

    #codes from: http://www.computer-engineering.org/ps2keyboard/scancodes2.html
    maps = {0x58:"CAPS", 0x1B:"s", 0x44: "o", 0x2d: "r", 0x35: "y", 0x41: ",", 0x29: " ", 0x59: "R SHIFT", 0x43: "i", 0x23: "d", 0x31: "n", 0x52: "'", 0x2c: "t", 0x4d: "p", 0x24: "e", 0x1c: "a", 0x42: "k", 0x12: "L SHIFT", 0x32: "b", 0x49: "."}

    caps = False
    skip = False
    once = False
    result = ""
    for i in range(0,len(codes)):
    	if skip:
    		skip = False
    		continue
    	c = codes[i]
    	c = ord(c)
    	if c == 0xf0:
    		skip = True
    		i = i +1
    		c = ord(codes[i])
    		if c == 0x59 or c == 0x12:
    			caps = False
    		continue
    	if c == 0x59 or c == 0x12:
    		caps = True
    		once = True
    		continue
    	if c == 0x58:
    		caps = caps == False
    		once = False
    		continue
    	if caps:
    		result = result + maps[c].upper()
    	else:
    		result = result + maps[c]
    	if once:
    		once = False

    print result

[/code]

After running the script we get the password: `Sorry, I don't speak Keyboard.`

* * *

  1. there are some typos in the document like using O instead of 0 here and there ↩︎

