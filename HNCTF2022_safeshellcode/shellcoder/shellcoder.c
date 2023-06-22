#include<stdio.h>
char buff[0x200];
int main()
{
    setbuf(stdin,0);
    setbuf(stderr,0);
    setbuf(stdout,0);
    mprotect((long long)(&stdout)&0xfffffffffffff000,0x1000,7);
    char buf[0x200];
    memset(buf,0,0x200);
    read(0,buf,0x300);
    for(int i=0;i<strlen(buf);i++){
        if(buf[i]<'0'||buf[i]>'z'){
            puts("Hacker!!!");
            exit(0);
        }
    }
    strcpy(buff,buf);
    ((void (*)(void))buff)();
    return 0;
}
