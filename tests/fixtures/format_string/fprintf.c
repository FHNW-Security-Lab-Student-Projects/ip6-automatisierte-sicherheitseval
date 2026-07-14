#include <stdio.h>
#include <string.h>

void log_error(char *user_input) {
    fprintf(stderr, user_input); 
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        log_error(argv[1]);
    }
    return 0;
}