#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void log_message(char *user_msg) {
    printf("%s", user_msg);
}

int main() {
    char input[256];
    printf("Enter a message: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;
    log_message(input);
    return 0;
}