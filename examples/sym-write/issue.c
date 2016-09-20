#include <stdio.h>

char u=0;
int main(void)
{
	int i, bits[2]={0,0};
	for (i=0; i<8; i++) {
		bits[(u&(1<<i))!=0]++;
	}
	if (bits[0]==bits[1]) {
		printf("you win!");
	}
	else {
		printf("you lose!");
	}
	return 0;
}
