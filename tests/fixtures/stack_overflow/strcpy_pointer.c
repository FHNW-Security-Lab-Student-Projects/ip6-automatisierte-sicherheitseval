#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void copy_input(char *user_input) {
    char dest[32];
    strcpy(dest, user_input);
}
int main(int argc, char **argv) {
    if (argc > 1) {
        copy_input(argv[1]);
    }
}