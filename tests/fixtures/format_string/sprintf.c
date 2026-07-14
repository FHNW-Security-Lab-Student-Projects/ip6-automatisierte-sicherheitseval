#include <stdio.h>
#include <string.h>

void create_message(char *user_data) {
    char buffer[256];
    
    sprintf(buffer, user_data); 
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        create_message(argv[1]);
    }
    return 0;
}