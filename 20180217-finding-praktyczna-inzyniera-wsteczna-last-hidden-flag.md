---
title: "Finding 'Praktyczna Inżyniera Wsteczna' last hidden flag."
date: 2018-02-17T08:53:38.000Z
tags:
  - "gynvael"
  - "book"
  - "praktyczna-inzynieria-wsteczna"
  - "flag"
  - "solution"
feature_image: "content/images/2018/02/PiWo_cover.webp"
---

# Finding "Praktyczna Inżyniera Wsteczna" last hidden flag.

If you read this blog you can see that from time to time I participate in missions published by Gynvael Coldwind on his [English](https://www.youtube.com/GynvaelEN) and [Polish](https://www.youtube.com/user/GynvaelColdwind) streams. You might not know that he is an author of 2 (one self, one co-op) books in the similar topics that he presents on streams. Those are: "Zrozumieć programowanie" (ZP) and "Praktyczna inżyniera wsteczna" (PIW). You might also not know that you can find missions or challenges. One famous one being the one on the front page of the PIW. You can read about it [here](https://vulnsec.com/2017/reverse-engineering-a-book-cover/).

Numerous times on streams, Gynvael mentioned, that there is still one puzzle hidden in the PIW book yet not found. I've decided to give it a try.

I've already read the book last year (my review - in Polish - you can watch [here](https://www.youtube.com/watch?v=IQuFuWvlXSc)), so in hunt for this puzzle I did not wanted to read it again (not that the book is not good :]). I've needed another approach. I got a hunch that the puzzle will be in Gynvael's chapter (chapter 6, about Python), but wasn't sure. So the approach was to go page by page from the beginning, and if something catches my eye, I'll investigate it more to find out.

It was pretty mundane task I must say and I was almost quitting, when a particular phrase caught my eye. On page 187 there was an example of obfuscated python script that corresponds to this code
[code]
    def my_print(text):
      print text
    my_print("asdf");

[/code]

The obfuscated version looked like this:
[code]
    exec('x\x9c\xf3\xact\xcaK\r75\x8a\x0c\x0f+\xf6\xc9\xf5+Kr\x0f2N\x0c7\xcd\xf6\xc9s*\xf61v\xf3\x0c\x0f\t*\x08w\xf53\x00\xf2\xf3\x93\x1d\x0b\xb2\xa3\xc2#\xd3\x93"r\xd2\x92=\xbc
\x92\xf2\x02\xf3S\xdc\xc3LR\x9c\xb3\xcd\x9c3\x1d\xd3\xb9\xa0\x82\xe9`A\xc7\x82\x92\xd40\xcb\xf2\xe4\xdc\x9c\xd2\x14\xe7\xf4\xcc\xc8\x08\xbf\xec\xa8L\xcf\x02\xe7t[[.\x00K\xfc(\x1f)'.decode('zlib').decode('base64'))
[/code]

I don't know if the script looked suspicious to be considered for further analysis. Or it looked to long to be just the function. I think the description's wording looked more suspicious to me. Above the script you read (my translation from Polish & my highlighting) "...**could** be coded to the following form:".

This could word was a bit odd here. Why "could"? It might be that this obfuscation can produce multiple forms, but this was at least first good candidate for being a hidden flag. So what was to be done was to type those characters to Sublime Text, change `exec` to `print`, so that nothing is hidden from us and see.

I must say, I did not expect much. Imagine my surprise and raised heart beat when after executing it apart from the code above I saw a comment with an URL.
[code]
    print 'x\x9c\xf3\xact\xcaK\r75\x8a\x0c\x0f+\xf6\xc9\xf5+Kr\x0f2N\x0c7\xcd\xf6\xc9s*\xf61v\xf3\x0c\x0f\t*\x08w\xf53\x00\xf2\xf3\x93\x1d\x0b\xb2\xa3\xc2#\xd3\x93"r\xd2\x92=\xbc
\x92\xf2\x02\xf3S\xdc\xc3LR\x9c\xb3\xcd\x9c3\x1d\xd3\xb9\xa0\x82\xe9`A\xc7\x82\x92\xd40\xcb\xf2\xe4\xdc\x9c\xd2\x14\xe7\xf4\xcc\xc8\x08\xbf\xec\xa8L\xcf\x02\xe7t[[.\x00K\xfc(\x1f)'.decode('zlib').decode('base64')


    λ python piwo.py
    # gynvael.coldwind.pl/qHY4iXCt.php
    def my_print(text):
      print text
    my_print("asdf")
[/code]

Wow. Could that be it? No way. I've entered the url to the browser and to my surprise there it was.

> Niesamowite, ktoś to znalazł :)
>  (Amazing, someone found it :))

An instruction to send an e-mail with a secret code. Send the mail at 10:38 PM and 12 minutes later I knew. I found the last flag.

Voilà.
