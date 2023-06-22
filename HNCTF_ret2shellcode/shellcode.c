#include<stdio.h>
char buff[256];
int main()
{
    setbuf(stdin,0);
    setbuf(stderr,0);
    setbuf(stdout,0);
    mprotect((long long)(&stdout)&0xfffffffffffff000,0x1000,7);
    char buf[256];
    memset(buf,0,0x100);
    read(0,buf,0x110);
    strcpy(buff,buf);
    return 0;
}
