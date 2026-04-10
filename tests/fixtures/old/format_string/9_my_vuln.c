#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void log_message(char *user_msg) {
    printf(user_msg); // CRASH/HACK: user_msg enthält "%x %x %n"
}

int main() {
    char input[256];
    printf("Enter a message: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0; // Remove newline
    log_message(input);
    return 0;
}