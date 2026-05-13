#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void safe_function() {
    printf("Everything is safe.\n");
}

void secret_function() {
    printf("SECRET FUNCTION EXECUTED!\n");
}

struct Data {
    void (*func_ptr)();
    char buffer[32];
};

void vulnerable_function(char *user_input) {
    struct Data *obj = malloc(sizeof(struct Data));
    
    obj->func_ptr = safe_function;
    
    strcpy(obj->buffer, user_input);
    
    obj->func_ptr();
    
    free(obj);
}

struct DataFixed {
    char buffer[32];
    void (*func_ptr)();
};

void vulnerable_function_fixed(char *user_input) {
    struct DataFixed *obj = malloc(sizeof(struct DataFixed));
    obj->func_ptr = safe_function;
    
    strcpy(obj->buffer, user_input);
    
    obj->func_ptr();
    
    free(obj);
}

int main(int argc, char **argv) {
    char input[100];
    if (argc > 1) {
        strcpy(input, argv[1]);
        vulnerable_function_fixed(input);
    }
    return 0;
}