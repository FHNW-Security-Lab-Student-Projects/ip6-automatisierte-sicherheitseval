#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct User {
    char username[32];
    int is_admin;
};

int main() {
    struct User *user1;
    struct User *user2;

    user1 = calloc(1, sizeof(struct User));
    
    if (!user1) {
        printf("Allocation failed\n");
        return 1;
    }

    user2 = calloc(1, sizeof(struct User));
    if (!user2) {
        printf("Allocation failed\n");
        return 1;
    }

    strcpy(user1->username, "guest");
    user1->is_admin = 0;

    printf("Waiting for input...\n");

    gets(user1->username);

    if (user1->is_admin == 0x41414141) { // 'AAAA'
        printf("Access Granted! Admin privileges escalated via calloc overflow.\n");
        return 0;
    } else {
        printf("Access Denied. is_admin = %d\n", user1->is_admin);
        return 1;
    }
}