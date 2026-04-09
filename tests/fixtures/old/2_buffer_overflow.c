#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    
    char buffer[64];
    int access_granted = 0;

    gets(buffer);

    if (access_granted != 0) {
        printf("Access granted!\n");
        exit(0);
    } else {
        printf("Access denied!\n");
        exit(1);
    }
}