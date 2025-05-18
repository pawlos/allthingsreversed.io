---
title: "Flare-On 2019 solutions/notes (upd. 11.02)"
date: 2019-11-21T15:31:08.000Z
tags:
  - "flare-on"
  - "flare"
  - "reversing"
  - "debugging"
feature_image: "content/images/2019/11/flare-on2019.webp"
---

# Flare-On 2019 solutions/notes (upd. 11.02)

I'm well aware that there's multiple write-ups/solutions presenting 2019's Flare-On solutions but I've decided to provide my own for two reasons. Firstly, to have some notes I can easily find for future. Secondly, I think some of my solutions were non-standard so it might be useful in some other cases for other reversers not only for me.

So here's my notes for the 11 tasks (the post will be updated as a publish the recordings) I did solve in 2019 edition of Flare-On's challenge:

## Memecat battlestation

[Watch on YouTube](https://www.youtube.com/watch?v=o9D5iwa99B4)

**Notes:** .net binary, with 3 stages, 2nd stage simple xor, 3rd stage - RC4
[code]
    import base64

    data = [95,193,50,12,127,228,98,6,215,46,200,106,251,121,186,119,109,73,35,14,20]#base64.b64decode("")
    data = [chr(x) for x in data]
    key = 'QmFnZWxfQ2Fubm9u'

    S = list(range(256))
    j = 0
    out = []

    #KSA Phase
    for i in range(256):
        j = (j + S[i] + ord( key[i % len(key)] )) % 256
        S[i] , S[j] = S[j] , S[i]

    #PRGA Phase
    i = j = 0
    for char in data:
        i = ( i + 1 ) % 256
        j = ( j + S[i] ) % 256
        S[i] , S[j] = S[j] , S[i]
        out.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))

    print(''.join(out))
[/code]

**Tools used:** dnSpy, python for decoding an RC4 encoded message for stage 3
**Tags:** dnSpy, RC4, .net, encryption

## Overlong

[Watch on YouTube](https://www.youtube.com/watch?v=TROwAkJNdbc)

**Notes:** binary with simple encryption algorithm that is decoding only part of the data
**Tools:** Ghidra, x32dbg
**Tags:** ghidra, x32dbg, encryption

## Flarebear

[Watch on YouTube](https://www.youtube.com/watch?v=M8Cy2sc9Dww)

**Notes:** java apk with non-standard AES encryption scheme (AES/CBC/PKCS7Padding)
**Tools:** java decompiler, text editor
**Tags:** java, bouncy castle, aes, cbc, PKCS7Padding

[View Gist](https://gist.github.com/pawlos/4245cbca80944e246ce6d6b614389083)

## Dnschess

[Watch on YouTube](https://www.youtube.com/watch?v=n0-vaRm1_ug)

**Notes:** pcap with DNS request & responses, binary with shared object that explains the logic behind the requests.
**Tools:** wireshark, ghidra, python
**Tags:** wireshark, ghidra, reversing, reverse engineering, DNS, pcap

[View Gist](https://gist.github.com/pawlos/eeb1d82d42196b37f44c3ac3a4f66b30)

## demo

[Watch on YouTube](https://www.youtube.com/watch?v=Dn8byTPeGRE)

**Notes:** 3d app, dump data, import to blender
**Tools:** x32dbg, python, blender
**Tags:** 3d,**** x32dbg, python, blender
[code]
    import struct

    cv = 0
    ci = 0
    with open('output3.txt','w') as o:
    	with open('mesh2_vertices.bin','rb') as f:
    		data = f.read()
    		#print(len(data))
    		i = 0
    		o.write("Vertex
")
    		while i < len(data)/24:
    			p = i*24
    			x = struct.unpack("f", data[p:p+4])[0]
    			y = struct.unpack("f", data[p+4:p+2*4])[0]
    			z = struct.unpack("f", data[p+2*4:p+3*4])[0]
    			#print(x,y,z)
    			o.write('{},{},{}
'.format(x,y,z))
    			i += 1
    			cv += 1

    	with open('mesh2_indices.bin', 'rb') as f:
    		data = f.read()
    		i = 0
    		o.write("Indices
")
    		while i < len(data)/12:
    			p = i*12
    			idx1 = struct.unpack("I", data[p:p+1*4])[0]
    			idx2 = struct.unpack("I", data[p+1*4:p+2*4])[0]
    			idx3 = struct.unpack("I", data[p+2*4:p+3*4])[0]
    			#print(idx1, idx2, idx3)
    			o.write("{},{},{}
".format(idx1, idx2, idx3))
    			i +=1
    			ci +=1


    print ("Vertex: {}, Indices: {}".format(cv, ci))
[/code]
[code]
    import bpy
    from mathutils import Vector
    import sys

    file = open("c:\\temp\\FlareOn\\2019\\challenges\\demo\\output3.txt")

    v = True
    i = False
    verts = []
    faces = []
    for l in file.read().splitlines():
    	if "Vertex" in l:
    		continue
    	if "Indices" in l:
    		v = False
    		i = True
    		continue
    	a = l.split(",")
    	if v:
    		scale = 1.0000
    		x=float(a[0])
    		y=float(a[1])
    		z=float(a[2])
    		newVertex= (x*scale,y*scale,z*scale)
    		verts.append(newVertex)
    	if i:
    		faces.append((int(a[0]),int(a[1]),int(a[2])))

    #print(faces)
    #print(verts)
    mesh_data = bpy.data.meshes.new("cube_mesh_data")
    mesh_data.from_pydata(verts, [], faces)
    mesh_data.update()

    obj = bpy.data.objects.new("My_Object", mesh_data)

    scene = bpy.context.scene
    scene.collection.objects.link(obj)
[/code]

## bmphide

[Watch on YouTube](https://www.youtube.com/watch?v=st0ldsUZ_QA)

**Notes:**.net application that encrypts some data plus stores then inside image. Some interesting runtime code modifications to prevent analysis.
**Tools:** dnspy, python
**Tags:** steganography**,** dnspy

[View Gist](https://gist.github.com/pawlos/a4893719aa2b36d497ab820b52204d2d)
[code]
    array = [121,255,214,60,106,216,149,89,96,29,81,123,182,24,167,252,88,212,43,85,181,86,108,213,50,78,247,83,193,35,135,217,0,64,45,236,134,102,76,74,153,34,39,10,192,202,71,183,185,175,84,118,9,158,66,128,116,117,4,13,46,227,132,240,122,11,18,186,30,157,1,154,144,124,152,187,32,87,141,103,189,12,53,222,206,91,20,174,49,223,155,250,95,31,98,151,179,101,47,17,207,142,199,3,205,163,146,48,165,225,62,33,119,52,241,228,162,90,140,232,129,114,75,82,190,65,2,21,14,111,115,36,107,67,126,80,110,23,44,226,56,7,172,221,239,161,61,93,94,99,171,97,38,40,28,166,209,229,136,130,164,194,243,220,25,169,105,238,245,215,195,203,170,16,109,176,27,184,148,131,210,231,125,177,26,246,127,198,254,6,69,237,197,54,59,137,79,178,139,235,249,230,233,204,196,113,120,173,224,55,92,211,112,219,208,77,191,242,133,244,168,188,138,251,70,150,145,248,180,218,42,15,159,104,22,37,72,63,234,147,200,253,100,19,73,5,57,201,51,156,41,143,68,8,160,58]

    def _f(idx, num2):
    	global array
    	num = idx
    	result = 0

    	#for i in range(idx+1):
    	num +=1
    	num %= 256
    	num2 += array[num]
    	num2 %= 256
    	num3 = array[num]
    	array[num] = array[num2]
    	array[num2] = num3
    	result = array[(array[num] + array[num2]) % 256] % 256
    	#print("Idx: {}, result: {}, num: {}, num2: {}".format((array[num] + array[num2]) % 256, result, num, num2))
    	return (result, num2)

    def _g(idx, a):
    	b = ((idx + 1) * 0x126b6fc5) % 256
    	k = ((idx + 2) * 0xc82c97d) % 256
    	return (b ^ k, a)
[/code]

## wopr

[Watch on YouTube](https://www.youtube.com/watch?v=Rs7_Y1GSRhk)

**Notes:** python script converted to/hidden inside exe, solving xor equations with z3 plus dumping some process data with python
**Tools:** python, Process Hacker
**Tags:** z3, python, Process Hacker, md5

[View Gist](https://gist.github.com/pawlos/ab270625d85c5074f1677d94cb961cea)  [View Gist](https://gist.github.com/pawlos/f044fde1cb78dda8d05cad4841da4efd)

## snake

[Watch on YouTube](https://www.youtube.com/watch?v=12B8nGCg468)

**Notes:** Snes game analyzed in ghidra and run in FCEUX emulator.
**Tools:** ghidra, fceux,
**Tags:** 6502, ghidra, nes, snes, game, snake, emulation

## reloaderd

[Watch on YouTube](https://www.youtube.com/watch?v=fRXQgpzXbbA)

**Notes:** program that fails Ghidra disassembly, shows different disassembly than running
**Tools:** Ida 7 Free, x32dbg, python
**Tags:** ida, python, x32dbg
[code]
    from itertools import *
    import string


    def xor(data, key):
    	return ''.join([chr(d ^ ord(k)) for d,k in zip(data, cycle(key))])

    data = [0x1C,0x5C,0x22,0x00,0x00,0x17,0x02,0x62,0x07,0x00,0x06,0x0D,0x08,0x75,0x45,0x17,0x17,0x3C,0x3D,0x1C,0x31,0x32,0x02,0x2F,0x12,0x72,0x39,0x0D,0x23,0x1E,0x28,0x29,0x69,0x31,0x00,0x39]

    extra = '_'+'-'+'$' +'!'+'@'+'*'+'.'
    valid = string.ascii_letters + string.digits + extra
    letters = string.ascii_letters+string.digits

    for x,y,z,a,b in product(letters, repeat=5):
    	if ord(x) ^ ord(y) != 0x41:
    		continue
    	if ord(z) & 1 == 1:
    		continue
    	if ord(b) * 0xc800 - 0x520800 >= 3:
    		continue
    	if (ord(a)*3 - 246) >= 2:
    		continue
    	key = a+'oT'+x+y+z+'eR'+b+'nG'
    	res = xor(data, key)
    	if not all([c in valid for c in res]):
    		continue
    	if '.com' in res.lower():
    		print('{0} -> {1}'.format(key, res))

[/code]

## MugatuWare

[Watch on YouTube](https://www.youtube.com/watch?v=xVBQHVQrmCE)

**Notes:** Malware with broken imports, XTEA used as an algorithm to encrypt GIF files.
**Tools:** Ghidra, x32dbg, python
**Tags:** mugatu, xtea,
[code]
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import base64
    from io import BytesIO


    def compress(data):
    	d = [x ^ 0x4d for x in data]
    	return base64.b64encode(bytearray(d))

    class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'Hello, world!')

        def do_POST(self):
            d = open('MugatuWare\\the_key_to_success_0000.gif.Mugatu','rb').read()
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            self.send_response(200)
            self.end_headers()
            response = BytesIO()
            response.write(compress(bytearray('orange mocha frappuccino\0','utf8')+d))
            #print(body)
            self.wfile.write(response.getvalue())


    httpd = HTTPServer(('localhost', 80), SimpleHTTPRequestHandler)
    httpd.serve_forever()
[/code]

[View Gist](https://gist.github.com/pawlos/e34876102af6cdcff63705ca27ee2a79)

## vv_max

[Watch on YouTube](https://www.youtube.com/watch?v=ub1Z63rsMA0)

**Notes:** vm solved by using complex z3 equation
**Tools:** ghidra, python, x64dbg, z3
**Tags:** ghidra, avx, virtual machine, vm

[View Gist](https://gist.github.com/pawlos/ebf753484ff62c908bc3df60f50bae35)
