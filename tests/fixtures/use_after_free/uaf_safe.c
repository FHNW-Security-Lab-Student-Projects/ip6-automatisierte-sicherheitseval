#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    void (*func_ptr)(void);
    char data[32];
} Victim;

void safe_function() {
    printf("Safe function called.\n");
}

void hacked_function() {
    printf("Hacked function called.\n");
}

int main() {
    Victim *v = (Victim *)malloc(sizeof(Victim));
    v->func_ptr = safe_function;
    strcpy(v->data, "Original Data");

    free(v);

    Victim *fake = (Victim *)malloc(sizeof(Victim));
    fake->func_ptr = hacked_function;
    strcpy(fake->data, "Attacker Data");

    v = NULL;

    printf("Triggering UAF attempt...\n");
    if (v != NULL) {
        v->func_ptr();
    } else {
        printf("Pointer was nulled, no UAF possible.\n");
    }

    return 0;
}