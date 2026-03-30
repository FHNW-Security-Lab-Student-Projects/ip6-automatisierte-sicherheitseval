#include <stdio.h>
#include <stdlib.h>

int main (int argc, char ** argv ){
    char buffer [20];
    scanf("%8s", buffer );
    for(int i = 0; i < 20; ++i){
        if(buffer[i] != i+"a"){
            printf("Tryagain");
            exit ( -1);
        }
    }
    printf("Good Job");
    return 0;
}