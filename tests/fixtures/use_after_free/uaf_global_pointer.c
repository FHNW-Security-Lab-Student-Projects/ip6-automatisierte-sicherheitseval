#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    void (*func_ptr)(void);
    char data[32];
} Item;

Item *g_item = NULL;

void safe_function() {
    printf("Safe function called.\n");
}

void hacked_function() {
    printf("VULNERABILITY EXPLOITED: Hacked function called!\n");
}

int main() {
    g_item = (Item *)malloc(sizeof(Item));
    g_item->func_ptr = safe_function;
    strcpy(g_item->data, "Original Data");

    free(g_item);

    Item *fake = (Item *)malloc(sizeof(Item));
    fake->func_ptr = hacked_function;
    strcpy(fake->data, "Attacker Data");

    printf("Triggering UAF...\n");
    if (g_item != NULL) {
        g_item->func_ptr();
    }

    return 0;
}