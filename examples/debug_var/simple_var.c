#include<stdio.h>

int global_var = 100;
int main(void){
	int a = 10;
	int* b = &a;
	printf("%d\n", *b);
	{
		int a = 24;
		*b = *b + a;
		int c[] = {5, 6, 7, 8};
		printf("%d\n", *b);
	}
	return 0;
}
