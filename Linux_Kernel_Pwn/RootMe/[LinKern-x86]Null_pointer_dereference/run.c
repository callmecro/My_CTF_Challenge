#include <unistd.h>

/* setuid script wrapper */ 

int main()
{
    char *argv[] = { "._start_vm", NULL };
    execve(argv[0], argv, NULL);
    return 0;
}

