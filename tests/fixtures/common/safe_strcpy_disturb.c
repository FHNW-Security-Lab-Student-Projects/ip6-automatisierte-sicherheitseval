#include <stdio.h>
#include <string.h>

void irrelevant_function() {
    char waste_buffer[128];
    printf("This function does nothing important.\n");
}

void safe_function(char *user_input) {
    irrelevant_function();
    char dest[32];
    irrelevant_function();
    
    if (strlen(user_input) < sizeof(dest)) {
        strcpy(dest, user_input);
        printf("Safe copy: %s\n", dest);
    } else {
        printf("Input too long! Rejected.\n");
    }
}

int main(int argc, char **argv) {
    if (argc > 1) {
        safe_function(argv[1]);
    }
    return 0;
}