#include<stdio.h>
char buff[100];
int v0;
char buffff[]="ABCDEFGHIJKLMNOPQRSTUVWXYZ1234";
char bua[]="abcdefghijklmnopqrstuvwxyz4321";
char* enccrypt(char *buf){
    int a;
    for(int i=0;i<29;i++){
        a=rand();
        buf[i]^=buffff[i];
        buff[i]^=bua[i];
        for(int j=29;j>=0;j--){
            buf[j]=buff[i];
            buf[i]+='2';
        }
        buf[i]-=((bua[i]^0x30)*(buffff[i]>>2)&1)&0xff;
        buf[i]+=(a%buff[i])&0xff;
    }
}
int main(){
    setbuf(stdin,0);
    setbuf(stderr,0);
    setbuf(stdout,0);
    puts("GDB-pwndbg maybe useful");
    char buf[]="Ayaka_nbbbbbbbbbbbbbbbbb_pluss";
    strcpy(buff,buf);
    char test[30];
    int v0=1;
    srand(v0);
    enccrypt(buff);
    read(0,test,30);
    if(!strncmp(buff,test,30)){
        system("/bin/sh");
    }
    else {
        puts("Oh No!You lose!!!");
        exit(0);
    }
    return;

}
