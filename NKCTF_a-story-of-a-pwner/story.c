#include <stdio.h>

char comment[40];
int a,b,c,d,e,f,g,opt;

void init() {
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
}

void menu() {
	puts("1.childhood")
	puts("2.childhood")
	puts("3.childhood")
	puts("4.childhood")
	puts("5.childhood")
	puts("6.childhood")
	puts("7.childhood")
	puts("8.childhood")
	puts("> ")
	scanf("%d", &opt);
}

void child() {
	read(0, *(comment + 8), 8);
	a = 1;
}

void MS() {
	read(0, comment, 8);
	b = 1;
}

void HS() {
	read(0, *(comment + 24), 8);
	c = 1;
}

void Uone() {
	read(0, *(comment + 16), 8)
	char commentUone[10];
	read(0, commentUone, 0x20);
}

void Utwo() {
}

void love() {
}

void acm() {
}

void ctf() {
}

int main() {
	init();
	puts("today, I want to tell you some stories about myself.")
	puts("I have a lot of stories, which one do you want to hear?")
	while (1) {
		menu();
		if (opt == 1) {
			child();
			break;
		}
		else if (opt == 2) {
			MS();
			break;
		}
		else if (opt == 3) {
			HS();
			break;
		}
		else if (opt == 4) {
			if (!(a && b && c)) {
				puts("Before u read this, i think u should read first 3.")
				break;	
			}
			Uone();
			break;
		}
		else if (opt == 5) {
			Utwo();
			break;
		}
		else if (opt == 6) {
			love();
			break;
		}
		else if (opt == 7) {
			acm();
			break;
		}
		else if (opt == 8) {
			ctf();
			break;
		}
		else {
			puts("wrong choice.")
			puts("you hurt me so much.")
			puts("DO YOU THINK IT'S FUNNY TO CHOOSE INCORRECT OPTION?")
			puts("BYE.")
			exit(0);
		}
	}
	return 0;
}
