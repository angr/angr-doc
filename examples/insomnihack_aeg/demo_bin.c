#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

char component_name[128] = {0};

typedef struct component {
    char name[32];
    int (*do_something)(int arg);
} comp_t;

int sample_func(int x) {
    printf(" - %s - recieved argument %d\n", component_name, x);
}

comp_t *initialize_component(char *cmp_name) {
    int i = 0;
    comp_t *cmp;

    cmp = malloc(sizeof(struct component));
    cmp->do_something = sample_func;

    printf("Copying component name...\n");
    strcpy(cmp->name, cmp_name);

    cmp->name[i] = '\0';
    return cmp;
}

int main(void)
{
    comp_t *cmp;

    printf("Component Name:\n");
    read(0, component_name, sizeof component_name);
    
    printf("Initializing component...\n");
    cmp = initialize_component(component_name);    

    printf("Running component...\n");
    mprotect((void*)((long)&component_name & ~0xfff), 0x1000, PROT_READ | PROT_EXEC);
    cmp->do_something(1);
}
