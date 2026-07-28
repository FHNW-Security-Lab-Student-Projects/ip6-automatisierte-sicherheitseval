#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLAGSIZE_MAX 64

int num_allocs;
char *x;
char *input_data;

void win() {
    char buf[FLAGSIZE_MAX];
    FILE *fd = fopen("flag.txt", "r");
    fgets(buf, FLAGSIZE_MAX, fd);
    printf("%s\n", buf);
    fflush(stdout);

    exit(0);
}

void check_win() { ((void (*)())*(int*)x)(); }

void print_menu() {
    printf("\nHello! Welcome to the challenge!\n");
    fflush(stdout);
}

void init() {

    printf("\nI have no information\n");
    fflush(stdout);

    input_data = malloc(5);
    strncpy(input_data, "pico", 5);
    x = malloc(5);
    strncpy(x, "bico", 5);
}

void write_buffer() {
    printf("Data for buffer: ");
    fflush(stdout);
    scanf("%s", input_data);
}

void print_heap() {
    printf("Nothing to see here\n");
    fflush(stdout);
}

int main(void) {

    init();

    int choice;

    while (1) {
        print_menu();
	if (scanf("%d", &choice) != 1) exit(0);

        switch (choice) {
        case 1:
            print_heap();
            break;
        case 2:
            write_buffer();
            break;
        case 3:
            printf("\n\nx = %s\n\n", x);
            fflush(stdout);
            break;
        case 4:
            check_win();
            break;
        case 5:
            return 0;
        default:
            printf("Invalid choice\n");
            fflush(stdout);
        }
    }
}
