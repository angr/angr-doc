#include <stdio.h>
#include <stdlib.h>

typedef void (*printFunction)();

// Contrived structure
typedef struct myStruct {
    printFunction print;
    char buf[16];
} myStruct;

// We want to get here
void win() {
    printf("Win function executed.");
}

int main() {
    // Unbuffering to make things clearer
    setbuf(stdin,0);
    setbuf(stdout,0);

    // Setup our two structs
    myStruct *a = calloc(1,sizeof(myStruct));
    myStruct *b = calloc(1,sizeof(myStruct));

    // Read in input
    printf("Input b: ");
    fgets(b->buf,64,stdin);
    b->print = printf;

    printf("Input a: ");
    fgets(a->buf,64,stdin);
    a->print = printf;

    // Print the results
    b->print("Output b: %s",b->buf);
    a->print("Output a: %s",a->buf);
}
