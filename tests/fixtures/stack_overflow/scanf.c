#include <stdio.h>
#include <string.h>

void vulnerable_login() {
    char username[32];
    char password[32];
    
    printf("Enter username: ");
    
    scanf("%s", username); 
    
    printf("Enter password: ");
    scanf("%s", password);
    
    printf("Welcome, %s!\n", username);
}

int main() {
    vulnerable_login();
    return 0;
}