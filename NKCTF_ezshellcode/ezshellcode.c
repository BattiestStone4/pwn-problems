#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

char buf2[100];

int main(void)
{
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin, 0LL, 1, 0LL);

    char buf[100];
    mprotect(0x404000, 0x1000, 7);

    puts("welcome to NKCTF!");
    puts("u can make it in 5 min!");
    read(0,buf,0x100);
    strncpy(buf2, buf, strlen(buf));
    puts("good luck!");
    int offset = (rand() % 100) + 1;
    ((void (*)())(buf2+offset))();

    return 0;
}
//gcc ret2shellcode.c -fno-stack-protector -o ret2shellcode -m32 -mpreferred-stack-boundary=4 -no-pie

