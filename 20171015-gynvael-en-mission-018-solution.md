---
title: "GynvaelEN - Mission 018 - Solution"
date: 2017-10-15T17:34:55.000Z
tags:
  - "gynvael"
  - "mission"
  - "solution"
feature_image: "content/images/2017/10/Zrzut-ekranu-2017-10-15-o-19.18.46.webp"
---

# GynvaelEN - Mission 018 - Solution

This is an another [GynvaelEN mission](https://www.youtube.com/watch?v=adHOlKKbFXM) solution. This time, the [task is simple](http://goo.gl/2MYXfu). We're given a script and we need to find the correct password to get the flag.
[code]
    Your flag: **$FLAG_ADMIN**
     ");
      } else {
        echo "MD5: " . md5($_GET['password1']) . "
    ";
        echo "SHA1: " . sha1($_GET['password2']) . "
    ";
        die ("You don't look like an admin.");
      }
    } else {
      show_source('admin.php');
    }

[/code]

The script is a simple MD5/SHA1 comparison that uses a weak equals operator (`==`) and we can exploit that. The additional problem here is that those hashes are quite specific. The format might be somewhat familiar. If you look closely you can notice that they are: `0e<digits>`. Apart from being a valid hash - those are valid numbers, only written in exponential form. So this is just 0 raised to a big number. So what we need to do is to find another hash that starts with `0e`. If we get that the weak comparison will return true. We could do the hashing ourself but this issue is not new. For MD5 we could do some searching on the internet and have some hits. So this is what I did and got a hit on this repository.

<https://github.com/spaze/hashes>

This repro actually describes this issue in details and has the examples of such hashes for both MD5 and SHA1! So we got both needed paswords for one search. Awesome. What just needs to be done is just curl:

> curl -v [http://gynvael.coldwind.pl/c3459750a432b7449b5619e967e4b82d90cfc971_mission018/admin.php?password1=QLTHNDT&password2=aaroZmOk](http://gynvael.coldwind.pl/c3459750a432b7449b5619e967e4b82d90cfc971_mission018/admin.php?password1=QLTHNDT&password2=aaroZmOk)

And that gives us the flag:

> I'm not sure this is how equality is supposed to work.

But that's not all. We see an additional message that informs us that there's a second stage of this task located at superadmin.php. If we navigate there, we see a simillar script but this time with sha256.

~~Unfortunatelly the simillar hashes are not to be found on the internet - so we need to hash it ourself. I;ve started doing this myself but it will take some time and might not result in any hits. Time will tell.~~

The second part become solvable when few SHA256 hashes were discovered to produce hashes in the form of `0e<digits>`. Sending one of those gives us the flag for stage 2: `Huh, this was supposed to be unsolvable.`.
