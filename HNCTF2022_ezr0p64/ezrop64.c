#include<stdio.h>
void vuln()
{
     char buf[0x100];
     printf("Gift :%p\n",&puts);
     puts("Start your rop.");
     read(0,buf,0x200);
     return;
}
int main()
{
     setbuf(stdin,0);
     setbuf(stderr,0);
     setbuf(stdout,0);
     puts("Easyrop.");
     vuln();
}
