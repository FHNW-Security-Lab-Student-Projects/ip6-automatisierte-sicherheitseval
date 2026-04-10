#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln(char *user_data) {
    char buf[50];
    sprintf(buf, "User: %s", user_data); // Overflow wenn user_data lang ist.
}

int main() {
    char input[100];
    printf("Enter your name: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0; // Remove newline
    vuln(input);
    return 0;
}