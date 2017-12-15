#include <stdio.h>
#include <stdlib.h>

// this function prints a secret
void printSecret() {
    printf("The secret is >1234<!\n");
}

// this function prints every entry of the collatz sequence, beginning with the number n
// it returns 1 or loops forever
long cheatedCollatzSequence(long n) {
    while(n != 1) {
        printf("%ld\n", n);
        if(n % 2 == 0) {
            n /= 2;
        } else {
            n = 3 * n + 1;
        }
    }
    return n;
}

int main(int argc, char **argv) {
    // print collatz sequence starting with number 837799 -> very long sequence -> path explosion
    long c = cheatedCollatzSequence(837799L);

    // read first command line argument as long
    char* ptr;
    long n = strtol(argv[1], &ptr, 10); // produces segfault if not specified

    // print secret if collatz-return-value and command-line-value add to lets say 123456
    if(c + n == 123456) {
        printSecret();
        return 0;
    } else {
        return 1;
    }
}