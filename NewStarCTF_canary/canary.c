#include<stdio.h>
#include<stdlib.h>
char fake[32]="/bin/sh";
int money=0;
void init()
{
setvbuf(stdin, 0LL, 2, 0LL);
setvbuf(stdout, 0LL, 2, 0LL);
setvbuf(stderr, 0LL, 2, 0LL);
}
void backdoor()
{
	system("echo 不是吧不是吧，该不会真的有人觉得会有后门给你吧"); 
}
int main()
{
	init();
	char vivo50[32];
	puts("Welcome to the zoo to adopt your canary");
	puts("If you v me 50, I will tell you the correct key");
	puts("Now answer me, will you v me 50");
	read(0,vivo50,0x20);
	printf(vivo50);
	puts("What do you want to say to the canary");
	read(0,vivo50,0x20);
	printf(vivo50);
	read(0,vivo50,money);
	return 0;
}
