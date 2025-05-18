---
title: "Qiwi Infosec CTF & RC3 CTF"
date: 2016-11-22T12:13:14.000Z
feature_image: "content/images/2016/11/Zrzut-ekranu-2016-11-22-o-13.13.39.webp"
---

# Qiwi Infosec CTF & RC3 CTF

Last week there were two CTFs I've participated in.

**Qiwi-Infosec CTF-2016** & **RC3 CTF 2016** were both quite an interesting. The first one, due to being during the week, I couldn't give as much hours as I could. In the second one I gave much more time & energy but it was worth it.

## Qiwi-Infosec CTF-2016

### Reverse_100_2 (Reverse 100)

> I have a [snake](). CrackMe!.

The file was a python compiled bytes. By using [uncompyle2](https://github.com/wibiti/uncompyle2) I was able to recover the .py file
[code]
    # 2016.11.22 11:24:48 CET
    #Embedded file name: task.py
    import marshal
    src = 'YwAAAAADAAAAGAAAAEMAAABz7wAAAGQBAGoAAGcAAGQCAGQDAGQEAGQFAGQGAGQHAGQIAGQJAGQKAGQLAGQMAGQNAGQOAGQPAGQMAGcPAERdHAB9AAB0AQB0AgB8AACDAQBkEAAXgwEAXgIAcToAgwEAfQEAdAMAZBEAgwEAfQIAfAIAfAEAawIAcuYAZAEAagAAZwAAZBIAZBMAZBQAZBUAZBYAZBcAZBgAZBkAZBoAZBsAZBwAZB0AZB4AZAsAZBwAZB8AZAMAZB0AZAgAZB4AZCAAZCEAZxYARF0VAH0AAHwAAGoEAGQiAIMBAF4CAHHGAIMBAEdIbgUAZCMAR0hkAABTKCQAAABOdAAAAAB0AQAAAF50AQAAADR0AQAAAEt0AQAAAGl0AQAAAC50AQAAAC90AQAAAE50AQAAAGp0AQAAAFB0AQAAAG90AQAAAD90AQAAAGx0AQAAADJ0AQAAAFRpAwAAAHMJAAAAWW91IHBhc3M6dAEAAABzdAEAAAB5dAEAAABudAEAAAB0dAEAAAA6dAEAAAB7dAEAAAB3dAEAAABxdAEAAABFdAEAAAA2dAEAAABmdAEAAABYdAEAAAB1dAEAAABhdAEAAAAxdAEAAAB9dAUAAABST1QxM3MFAAAATm8gOigoBQAAAHQEAAAAam9pbnQDAAAAY2hydAMAAABvcmR0CQAAAHJhd19pbnB1dHQGAAAAZGVjb2RlKAMAAAB0AQAAAGV0AwAAAHRtcHQGAAAAcGFzc3dkKAAAAAAoAAAAAHMHAAAAdGFzay5weVIcAAAAAgAAAHMKAAAAAAFfAQwBDAFvAQ=='.decode('base64')
    code = marshal.loads(src)
    exec code

[/code]

By adding `import dis` and changing `exec code` to `print dis.dis(code)` we are able to obtain the Python byte code.

[View Gist](https://gist.github.com/pawlos/893e22df5c712b0490b23fe265e8ad14)

As I can see the code is not that complex. After few minutes we can get the original python code:
[code]
    tmp = ''
    w = ''.join(['^','4','K','i','.','/','N','j','P','o','?','l','2','T','?'])
    for e in w:
    	tmp = tmp + chr(ord(e)+3)

    print 'You pass:'
    passwd = raw_input()

    if tmp == passwd:
    	t = ''.join(['s','y','n','t',':','{','w','q','E','6','f','X','u','o','f','a','4','X','N','u','1','}'])
    	w = ''
    	for e in t:
    		w = w + e.decode('ROT13')
    	print w
    else:
    	print "No :("
    return None
[/code]

What we can do now is either print the tmp variable to obtain the correct input (`a7Nl12QmSrBo5WB`) or just remove the check for correct input and get the correct flag: `flag:{jdR6sKhbsn4KAh1}`.

But the system did not accept this as I correct one. WTF? I was staring a bit at my analysis for another 30 minutes after I've realized that maybe I should provide only the part in the `{}` and yup. After removing `flag:{` and`}` the system did accept the flag.

## RC3 CTF

In this CTF I've started with some trivia tasks. I like those as they can give some easy points (that's not the main reason for liking them) but also can set yourself into challenges.

So in this CTF I've started with solving Trivias (one wasn't that trivial at all ;))

### What's your virus? (Trivia 20)

> This virus, once clicked, will send itself to everyone in the user’s mailing list and overwrite files with itself making the computer unbootable.

Well there are lots of viruses that can do that but I was looking for some most know ones.

Finally found out this most famous worm - [ILOVEYOU](https://en.wikipedia.org/wiki/ILOVEYOU). At first I discard this one as a valid solution as it was worm not a virus but the more I read about it I was more and more convinced. An finally this sentence

> while appending the additional file extension VBS, making the user's computer unbootable.
>  convinced me.

### Horse from Tinbucktu (Trivia 30)

> A Trojan horse that infects Windows computers, usually performing a man in the browser attack, key logging, and form grabbing

Ok, checking all the most known trojans I found out [Zeus](https://en.wikipedia.org/wiki/Zeus_\(malware\)) and this sentence from the description confirms the flag:

> by man-in-the-browser keystroke logging and form grabbing.

### Love Bomb (Trivia 40)

> This virus was created with the intension of disrupting the nuclear efforts of the Iranians

This one did not require even a second of searching. Who hasn't heard of [Stuxnet](https://en.wikipedia.org/wiki/Stuxnet).

### Infringing memes (Trivia 50)

> This proposed law suggested giving the United States government more power over infringing content. Websites like Reddit were up in arms over this as they thought this would give the government too much power.

At the beginning I thought this was going to be ACTA but that didn't work. I found out [this article](https://redditblog.com/2012/01/17/a-technical-examination-of-sopa-and-protect-ip/) about reddit but SOPA and PROTECT IP did not work either. I went on reading about those acts (omg!) and found out that PROTECT IP is also known as PIPA (good name ;) and that was the correct flag.

### Who's a good boy? (Web 100)

> You’re trying to see the cute dog pictures on ctf.rc3.club. But every time you click on one of them, it brings you to a bad gateway.
>  <https://ctf.rc3.club:3000/>
>  \-- Your friendly neighborhood webadmin

When opening the page you see a lot of Doge images.

![](content/images/2016/11/Zrzut-ekranu-2016-11-22-o-12.15.14.webp)

There's not much on the webpage itself or the headers but there's a CSS file link with the page. By getting it's content one can see at the very end the flag:

`/*hiya*/ /*compress your frontend*/ /*here's a flag :)*/ flag:RC3-2016-CanineSS`

so the flag is: `RC3-2016-CannieSS` and 100 points to us.

### Graphic Design (Forensics 200)

> The 3D Design students have been boasting about how they can trade sensitive information without anyone ever knowing. You’ve intercepted one of their USB’s and found this interesting file. Figure out what the hell is going on.
>  Download Link: <https://drive.google.com/file/d/0Bw7N3lAmY5PCTWg5YU1uNUk3cmc/view?usp=sharing>
>  -Your friendly neighborhood httpster

After downloading the file we see it's an obj file but after a closer inspection we see it's Blender file

> # Blender v2.78 (sub 0) OBJ File

So I've downloaded Blender and import it. And actually it worked. One could see a nice dinosaur (Stegosaurus) inside.

![](content/images/2016/11/Zrzut-ekranu-2016-11-22-o-12.25.55.webp)

but we can also see there's are other elements on the scene.

![](content/images/2016/11/Zrzut-ekranu-2016-11-22-o-12.28.19.webp)

after hiding the `stegosaurus` object we see this:

![](content/images/2016/11/Zrzut-ekranu-2016-11-22-o-12.29.26.webp)

So the flag is: `RC3-2016-St3GG3rz`

### Forensics 300

> We just received this transmission from our news correspondents. We need to find out what they are telling us.
>  Download Link: <https://drive.google.com/file/d/0B_AQp5s_S-khWjExSllLYjFRR0E/view?usp=sharing>
>  author:orkulus

After downloading the file we can see there are bunch of zip files in the tar archive. And in each zip file there's a txt file with part of the text transmission that gives this message

> Coming to you live from QuarfBlaaaark 7, this is Montgomery Flaaaargendach with Live Forensic Files: Raw Forensic Adventures.
>  Hello folks. Today we're going to take a trip on the wild side. We're going to try to figure out what happened to our favorite ducky superstar from QuarfBlaaaark 6.
>  That's right folks, Fluffles McSchloobdeboop has gone missing. She was last seen in entering a limousine at a night club.
>  Her father has ties to the Queebloid mafia family, which controls a majority of the traffic of a drug called quaaaack.
>  That's right folks, the crazy party drug named after the extended hallucinations that have caused people, just like yourselves, to start quacking uncontrollably.
>  We have reason to suspect that the Bleegle mafia family, which is vying for control of that drug market after the decline in the public use of moooooooooo, may be seeking to hold Fluffles McSchloobdeboop for ransom.
>  Let's go and find her. _3 hours of watching Montgomery Flaaaargendach drive around town screaming "FLUFFLES!!!!" later_
>  I think that we may have found their hideout. Let's go Jimmy.
>  As you can see right now, we have found the Bleegle mafia boss sitting in a chair. He doesn't look that happy.
>  Oh, his hands are tied? Wait, is that Fluffles? No, it can't be.
>  Fluffles has taken the head of the Bleegle family hostage, not the other way around.
>  It appears that this was an elaborate ruse played by the Queebloid mafia family to let Fluffles be captured and then hold the head of the Bleegle family for ransom.
>  Wow, these Queebloid folks do not fool around.
>  Oh, what's this? It seems that this has erupted in an all out gang war!!!!
>  *From off camera, Jimmy says: "Monty, no it's not. There's nobody named Fluffles McSchloobdeboop. That's a preposterous name.
>  Jimmy continues: And, you know what Monty? I've had enough of following you around with this thing. I'm tired of recording whatever you want me to.
>  I can't do this any more. Go back to your fantasy world now, because I'm going home.
>  *Montgomery slowly picks up the camera that Jimmy left on the ground. He looks deep into its lens.
>  It appears that the conspiracy runs deeper than I thought.
>  _Cut to black_

for a short wile I was searching for something hidden here but gave that up very quickly. And I've started looking at `.tar` & `.zip` files. By hex dumping the whole archive I've noticed something that can't be unrecognized.

> My0yMAo=

base64! So after careful analysis of the file I've extracted 5 base64 strings

> UkMK (Chapter4.zip)

> My0yMAo= (Chapter9.zip)

> MTYtRFUK (Chapter10.zip)

> QkxTCg== (Chapter18.zip)

which decoded to: `RC3-2016-DUKYFBLS`. For a while I did not checked it as a flag but finally gave it a try and it was actually the flag.

### Klaatu Brada N... (Misc 300)

> Whilst fighting of hordes of Deadites, Ash seems to have forgotten something. Help Ash remember the words, because he'd rather be in Jacksonville.
>  nc ctf.rc3.club 6050
>  author:orkulus

After connecting to the services we are flooded with base64 strings and the connection is closed.

[View Gist](https://gist.github.com/pawlos/c8f4a14852c1dfc333dccd4ccfdf52e8)

so first I've decoded them

[View Gist](https://gist.github.com/pawlos/c40aab5b687704362e7cb2b3b4a143fa)

it looks like some quotes from a movie. My searching for some of them in your favorite search engine it was obvious that they come from two zombie movies:

  * [Army of Darkness](http://www.imdb.com/title/tt0106308/)
  * [Evil Dead 2](http://www.imdb.com/title/tt0092991/)

Ok, so maybe the flag is coded as binary depending of the movie? Let's try it out.
[code]

    army_of_darkness = ["Oh, you wanna know? 'Cause the answer's easy! I'm BAD Ash... and you're GOOD Ash! You're a goody little two-shoes! Little goody two-shoes! Little goody two-shoes!",
    "Good. Bad. I'm the guy with the gun.",
    "Look, maybe I didn't say every single little tiny syllable, no. But basically I said them, yeah.",
    "Buckle up Bonehead. 'Cause you're goin' for a ride!",
    "Sure, I could have stayed in the past. I could have even been king. But in my own way, I *am* king.",
    "Honey, you got reeeal ugly!",
    "I don't want your book, I don't want your bullshit. Just send me back to my own time, pronto, today. Chop chop!",
    "Klaatu Barada N... Necktie... Neckturn... Nickel... It's an \"N\" word, it's definitely an \"N\" word! Klaatu... Barada... N...",
    "Yo, she-bitch! Let's go!",
    "Shut up, Linda!",
    "Boomstick: $199.99, Shells: 39.99, Zombies heads blowing off: priceless.",
    "Well hello Mister Fancypants. Well, I've got news for you pal, you ain't leadin' but two things, right now: Jack and shit... and Jack left town.",
    'I believe I have made a significant find in the Kandarian ruins, a volume of ancient Sumarian burial practices and funerary incantations. It is entitled "Naturum De Montum", roughly translated: Book of the Dead. The book is bound in human flesh and inked in human blood. It deals with demons and demon resurrection and those forces which roam the forest and dark bowers of Man\'s domain. The first few pages warn that these enduring creatures may lie dormant but are never truly dead.',
    "After all, I'm a man and you're a woman... at least last time I checked. Huh huh."
    ]
    evil_dead_2 = [
    "Alright you Primitive Screwheads, listen up! You see this? This... is my BOOMSTICK! The twelve-gauge double-barreled Remington. S-Mart's top of the line. You can find this in the sporting goods department. That's right, this sweet baby was made in Grand Rapids, Michigan. Retails for about a hundred and nine, ninety five. It's got a walnut stock, cobalt blue steel, and a hair trigger. That's right. Shop smart. Shop S-Mart. You got that?",
    "Oh that's just what we call pillow talk, baby, that's all.",
    "I may be bad... but I feel gooood.",
    "I'll swallow your soul! I'll swallow your soul! I'll swallow your soul! Swallow this.",
    "Groovy.",
    "I got it, I got it! I know your damn words, alright?",
    "I know you're scared; we're all scared, but that doesn't mean were cowards. We can take these skeletons, we can take them, with science."]
    army_bit = "0"
    evil_bit = "1"
    correct = "010100100100001100110011001011010011001000110000001100010011011000101101"
    output = ""
    import sys
    for l in open(sys.argv[1]):
    	st = l.rstrip('
')
    	if st in army_of_darkness:
    		output = output + army_bit
    	elif st in evil_dead_2:
    		output = output + evil_bit
    	elif len(st) != 0:
    		print "Empty: ", st

    	hm = min(len(correct),len(output))
    	if output[0:hm] != correct[0:hm]:
    		print output
    		print correct
    		print st
    		break
    import binascii
    print output
    n = int('0b'+output, 2)
    print binascii.unhexlify('%x' % n)
[/code]

There was some back and forth with few of the quotes but due to the fact that I knew the first chars of the flag (`RC-2016-`) I could verify the correctness of quotes assignment to the movies. After making it correct and running we get the flag:

`RC3-2016-CHRLSD3D`

Points in total: 1040.
