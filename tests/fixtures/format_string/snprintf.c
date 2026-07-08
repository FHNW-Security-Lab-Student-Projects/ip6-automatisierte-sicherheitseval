#include <stdio.h>
#include <string.h>

void safe_create_message(char *user_data) {
    char buffer[256];
    
    snprintf(buffer, sizeof(buffer), user_data);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        safe_create_message(argv[1]);
    }
    return 0;
}