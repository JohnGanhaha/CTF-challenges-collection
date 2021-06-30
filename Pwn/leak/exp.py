from pwn import *
from LibcSearcher import * 
context.log_level = 'debug'
 
#p=process('./4-ReeHY-main')
p= remote('111.200.241.244',64241)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
ReeHY = ELF('./4-ReeHY-main')
head_addr= 0x6020e0
