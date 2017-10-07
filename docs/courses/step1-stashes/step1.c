#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    int something = strlen(argv[1]);

    // stash avoided
    if(something == 1) {
        // some path explosion
        int a = 1;
        for(int i = 0; i < 10000; i++) {
            a += a;
        }
        return a;
    }

    // stash found
    if(something == 3) {
        printf("The End\n");
        return 0;
    }

    // stash active
    return 0;
}