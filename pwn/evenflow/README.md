# Even Flow

* **Category**: Pwn
* **Description**: _Do you like shell command injection?_

This was a shell command injection exploit (as can be told by the description), that required some creativity.

## Observing the source

Thankfully, we are given the source code, which is a Python file, as well as another binary written in C, with its source code in the comments:

The notable lines of the Python code and C code are:

```c
fread(buffer, 1, file_size, fd);
return strcmp(buffer, argv[1]);
```

```python
shell = sys.stdin.read(2)
assert(re.match("^[a-zA-Z0-9_{}]+$", flag) is not None)
os.system("./evenflow " + flag + "; echo \"" + shell + "\"")
```

We see that the injection points at `flag` and `shell` differ quite a lot. The first injection point is rather well protected since we can't inject semicolons, operators like `&` or `|`, and so on, and the second injection point is limited to two bytes.

## Shell variables

What can you do with two bytes? The first thing that comes to mind is shell variables, like `$1`, which is similar to `argv[1]` in C, and `$?` which gives the return code of the last command.

In particular, we are interested in `$?`, since when we use it with some input we can observe a nice pattern:

```sh
$ nc ctf.pwn.sg 1601
Flag: A
Shell: $?
2
$ nc ctf.pwn.sg 1601
Flag: B
Shell: $?
1
$ nc ctf.pwn.sg 1601
Flag: D
Shell: $?
255
$ nc ctf.pwn.sg 1601
Flag: E
Shell: $?
254
```

It looks like it's leaking the value of the flag, since we can guess it most likely begins with `CrossCTF{`.

## `strcmp`

We can dig deeper. We know that `strcmp()` performs string comparison byte for byte, and behaves as such:

* Returns 0: `s1` and `s2` are equal
* Positive integer: The stopping character in `s1` is less than `s2`
* Negative integer: The stopping character in `s1` is more than `s2`

Assuming an 8-bit integer in 2's complement, this means that the value of `255` from above is actually a negative integer in C (which corresponds to `-1`), `254` corresponding to `-2`, etc. This means that in this particular implementation of `strcmp()`, the distance between the stopping characters is being returned.

This means by passing in a string into the first input where we know that all characters except that the last are correct, the return value from the input above would give us the _distance of the char code of the actual character from our character, modulo 256_ (this is a useful property of 2's complement, which I hadn't realised before this).

## Scripting

With that done, we can enumerate every single character of the flag, using `A` as our test character. The script can be found [here](https://github.com/irvinlim/crossctf-2018-quals/blob/master/pwn/evenflow/pwn.py).

```sh
$ python exploit.py
[*] Reading characters: ..........................................
[*] The flag is: CrossCTF{I_just_want_someone_to_say_to_me}
```
