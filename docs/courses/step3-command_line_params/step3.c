#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    char* pass = "zardus";
    if(strncmp(argv[1] + 5, pass, strlen(pass)) == 0) {
        printf("You win the internet!\n");
    }
}