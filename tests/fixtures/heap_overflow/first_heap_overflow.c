#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Data {
    char buffer[32];
    int access_level;
};

int main() {
    struct Data *data1 = malloc(sizeof(struct Data));
    struct Data *data2 = malloc(sizeof(struct Data));

    data1->access_level = 0;
    data2->access_level = 0;

    printf("Waiting for input...\n");
    
    data2->access_level = 0x43434343;
    
    gets(data1->buffer);

    if (data1->access_level == 0x41414141) {
        printf("Access Granted! (Heap Overflow successful)\n");
        return 0;
    } else {
        printf("Access Denied.\n");
        return 1;
    }
}