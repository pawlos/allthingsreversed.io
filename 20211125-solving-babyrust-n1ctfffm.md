---
title: "babyRust - N1CTF"
date: 2021-11-25T20:13:26.000Z
tags:
  - "ctf"
  - "rusty"
  - "babyrust"
  - "n1ctf"
feature_image: "content/images/2021/11/004.webp"
---

# babyRust - N1CTF

This fun, little challenge was RE challenge during N1CTF.

We are given the following Rust source code:
{% raw %}
[code]
    macro_rules! check {
        (@s n1ctf{$Never:tt}) => {
            check!(stringify!($Never))
        };
        (@e ($Never:expr,$Gonna:expr,$Give:expr); (Never gonna give you up $($code:tt)*)) => {
            $Give += true as usize;
            check!(@e ($Never,$Gonna,$Give); ($($code)*));
        };
        (@e ($Never:expr,$Gonna:expr,$Give:expr); (Never gonna let you down $($code:tt)*)) => {
            $Give -= true as usize;
            check!(@e ($Never,$Gonna,$Give); ($($code)*));
        };
        (@e ($Never:expr,$Gonna:expr,$Give:expr); (Never gonna run around and desert you $($code:tt)*)) => {
            $Gonna += true as u8;
            check!(@e ($Never,$Gonna,$Give); ($($code)*));
        };
        (@e ($Never:expr,$Gonna:expr,$Give:expr); (Never gonna make you cry $($code:tt)*)) => {
            $Gonna -= true as u8;
            check!(@e ($Never,$Gonna,$Give); ($($code)*));
        };
        (@e ($Never:expr,$Gonna:expr,$Give:expr); (Never gonna say goodbye $($code:tt)*)) => {
            $Gonna = $Never[$Give];
            check!(@e ($Never,$Gonna,$Give); ($($code)*));
        };
        (@e ($Never:expr,$Gonna:expr,$Give:expr); (Never gonna tell a lie and hurt you $($code:tt)*)) => {
            $Never[$Give] = $Gonna;
            check!(@e ($Never,$Gonna,$Give); ($($code)*));
        };
        ($Never:expr) => {{
            fn check() -> bool {
                let mut never = $Never.as_bytes().to_vec();
                let mut gonna = false as u8;
                let mut give:usize = false as usize;
                check!(@e (never,gonna,give); (
                Never gonna say goodbye Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna tell a lie and hurt you Never gonna give you up Never gonna say goodbye Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna tell a lie and hurt you Never gonna give you up Never gonna say goodbye Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you Never gonna run around and desert you ...
                ));
            }
            check()
        }};
        (@e ($Never:expr,$Gonna:expr,$Give:expr); (Never gonna give never gonna give)) => {
            let you = [148u8, 59, 143, 112, 121, 186, 106, 133, 55, 90, 164, 166, 167, 121, 174, 147, 148, 167, 99, 86, 81, 161, 151, 149, 132, 56, 88, 188, 141, 127, 151, 63];
            return $Never == you;
        };
    }

    fn main() {
        let result = check!(@s /*your answer*/);
        if result {
            println!("Yes");
        }
    }

[/code]
{% endraw %}

(Full source code [here](https://gist.github.com/pawlos/079a3301174d2a322d99ae607cde1bf0)).

And of course our goal is to find the working flag, put it in the /*your answer*/ placeholder and validate.

To solve it we should probably understand Rust's macros but even without that knowledge we could find out how the challenge supposed to work. Each phrase starting with `Never` is resolved by a particular fragment and the specific code is executed.

For example, `Never gonna give you up` will work with variable `$Give` and it will increment it by 1, for `Never gonna let you down` is the opposite happens and so it. Apart from those two, there's also an phrase that reads from an array, and one that stores a value in it. It's a simple of Virtual machine with 6 instructions encoded as phrases from the song. Nice ;) The long list of phrases are of course, our opcodes and if the last one `up Never gonna give never gonna` we are comparing what we have with a constant array of values stored as `you`.

To get the flag, we can implement the loop starting with end values from `you`, and instead of incrementing the value when we have `Never gonna give you up` we subtract `1`. The same goes for where `1` was taken in the original code. With that approach, when we process all the -lyrics- opcodes, we should get the correct input.

The following python code does that:
[code]
    output = [148, 59, 143, 112, 121, 186, 106, 133, 55, 90, 164, 166, 167, 121, 174, 147, 148, 167, 99, 86, 81, 161, 151, 149, 132, 56, 88, 188, 141, 127, 151, 63]

    lines = open('lyrics.txt','r').readlines()

    i = 0
    c = 0
    import sys
    for l in lines:
    	if 'Never gonna say goodbye' in l:
    		c = output[i]
    	elif 'Never gonna run around and desert you' in l:
    		c -= 1 # do reverse
    		if c < 0:
    			c = 255
    	elif 'Never gonna tell a lie and hurt you' in l:
    		output[i] = c
    	elif 'Never gonna give you up' in l:
    		i += 1
    	elif 'Never gonna give never gonna give' in l:
    		break
    	else:
    		print(f'not found: {l}')
    		sys.exit(-1)
    print(output)
    print(''.join([chr(x) for x in output]))

[/code]

Running it will give `A6C33EA2571A2AE26BFAE7BEA2CD8F54` and adding `n1ctf{}` around it will give us the correct flag.
