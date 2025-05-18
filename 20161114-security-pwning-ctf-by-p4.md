---
title: "Security Pwning CTF by p4"
date: 2016-11-14T19:48:32.000Z
tags:
  - "ctf"
feature_image: "content/images/2016/11/Zrzut-ekranu-2016-11-14-o-20.50.06.webp"
---

# Security Pwning CTF by p4

A few days ago, I've attended a [Security PWNinng 2016](https://www.instytutpwn.pl/konferencja/pwning2016/) conference in Warsaw. There was a CTF during the event in which I took part and solved few tasks.

The CTF was organized by [p4 team](https://www.linkedin.com/company/p4-team). If you want to have a try it's still available at <https://pwning2016.p4.team>. It's in polish but I guess google translate can help here.

## Web 50 - Trawersujące koty (Traversing cats)

The name of the task already suggests the technique that should be used here. When we check the source of the webpage we can see that links to images are specified with file parameters that takes the path.

![](content/images/2016/11/Zrzut-ekranu-2016-11-14-o-19.17.14.webp)
Lets try to use it for our purpose and put there a path to potential flag file.

![](content/images/2016/11/Zrzut-ekranu-2016-11-14-o-19.20.25.webp)

Well, we got an error stating that the file is not in `/opt/web50_cats/static/traveling_cats/flag.txt`

What about home directory?

`https://cats.pwning2016.p4.team/view.html?file=../../../../home/cats/flag.txt`

Something more interesting here: `<img alt="Embedded Image" src="data:image/png;base64,cHdue2tvdHkuY3p5Lm5pZSx6YWRhbmllLnpyb2Jpb25lfQo=">`
and after base64 decode we get the first flag: `pwn{koty.czy.nie,zadanie.zrobione}`

## Web 50 - Moja pierwsza strona (My first website)

After visiting the webpage we end up on a login panel where we can see a message from an author:

> Hey admin, log in with your password.

> I wrote the code myself and used pretty nice SQL query for that, let's hope no one unauthorized gets through.

Let's try SQLi. Lets up "'" in a password field.

> Internal Server Error

Great! So let's log in:

username: admin
password: ' or 1=1--

which gives us the flag: `pwn{5ql1njecti0nByp@ssMade4@5y}`. A quick one.

## Stegano 50 - I'm going to space

In this task we're given a file which is a Wave file with Apollo13 radio transmission between Neil Armstrong and Huston Space Center. You know, the one with "That’s one small step for a man, one giant leap for mankind". As this is stegano and Wave file I suspect that some information might be hidden on LSB. But the first thing I always do in such case - I open the file in Audacity.

![](content/images/2016/11/Zrzut-ekranu-2016-11-14-o-19.34.44.webp)

we can see some high amplitude sounds. If we play them it sounds like there might be some info but changing the speed of playback does not give anything. Everything changes if we switch to spectrum view and zoom in to the same place we can clearly see the flag

![](content/images/2016/11/Zrzut-ekranu-2016-11-14-o-19.39.50.webp)

`pwn{$pace_Is_$o_Cool}`

## re 50 - Crack me

In this one we are given the windows binary file. Lets open it up in IDA (free).

In the strings we can easily find an interesting string `| < Brawo, podales poprawna flage` (which translates to: Congrats, you have given a correct flag). If we display xrefs we can see the code that check for the flag:

![](content/images/2016/11/Zrzut-ekranu-2016-11-14-o-20.00.34.webp)

by looking at the code we can see that the program asks for flag and PIN.

By examine the check we can see that the flag is 14 chars long (0xE) and from 4th to 13th char should be equal to `cr4ck3dm3`. Knowing that the flag should be in the form of pwn{sth} we deduce that the correct one is: `pwn{cr4ck3dm3}`.
The pin is compared to number 0x539 = 1337 dec. The flag from the app works as a final flag.

## web 100 - Loteria flagowa (Flag lottery)

In this one we're given a web page that selects 6 numbers from 10 to 99. Our task is to predict what is selected. If we do that correctly we will be given a flag.
[code]
    var express = require("express");
    var app = express();
    var expressWs = require('express-ws')(app);
    var fs = require("fs");

    var flag = fs.readFileSync("../flag").toString();

    app.use(express.static('.'));

    app.ws('/', function(ws, req) {
    	var seed = new Date().valueOf() & 0xFFFFFFFF;
    	var rnd = betterRand(seed)
        var userId = new Buffer(seed.toString()+","+rnd.next().value).toString("base64")

        var numbers = Array.from(Array(6)).map(() => Math.floor(rnd.next().value * 89 + 10))

        ws.on('message', function(msg) {
            try {
                var m = JSON.parse(msg.replace("'", '').replace("'", ''));
                var resp = {"numbers": numbers}

                if(JSON.stringify(resp.numbers) === JSON.stringify(m.numbers))
                    resp.flag = flag;

                console.log(resp);
                ws.send(JSON.stringify(resp));
            } catch(err) { }

            ws.close()
        });

        console.log("[*] Peer connected!");
        ws.send(JSON.stringify({"userId": userId}))
    });

    console.log("[*] Listening on port 5555...")
    app.listen(5555);

    function* betterRand(seed) {
      var m = 25, a = 11, c = 17, z = seed || 3;
      for(;;) yield (z=(a*z+c)%m)/m;
    }
[/code]

we can see there where the numbers are generated but also that a random seed, and the a number that it's before our 6 numbers to guess are send to the client. Ok. Looks like we go everything we need. Lets save the html file, correct the links to the resources and modify the Javascript. In the `.onMessage` method we add
[code]
    var msg = JSON.parse(evt.data);
    if(msg["userId"])
    {
      $("#user-id")[0].innerText = msg["userId"];
      a = window.atob(msg["userId"]);
      var s = a.split(",");
      var seed = s[0];
      var next = s[1];
      var rnd = betterRand(seed);

      while (rnd.next().value != next) ;
      var numbers = Array.from(Array(6)).map(() => Math.floor(rnd.next().value * 89 + 10))
      console.log(numbers);
    }
[/code]

and we paste the `betterRand` function form the server side. So basically what we do here we decode a `userId` information that is send from the server and that contains `seed` and a number before our 6 numbers to guess. then we construct a random and generate numbers until we hit our number that is send with the seed. After we get it we get the 6 numbers and print them in the console. Our only task is to write them from the console to the fields - we could automate that but there's no need.

Of course we could hit a value that is false-positive but in such case we re-run it again. It should produce correct numbers fairly quick. It worked the first time I run it.

The flag returned from the server after typing the numbers: `pwn{U5e_M0ar_53cuR3_4and0m}`.

Yup. Random here was the weak spot + that we were given the seed.

That's all the task that I had time solve - I wanted to actually listen to the talks :). But since the tasks are still there I think I'll attack them again. I need to work especially on the crypto ones.
