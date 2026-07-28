#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLAGSIZE_MAX 64

typedef struct {
  char a[10];
  char b[10];
  char c[10];
  char flag[5];
} object;

int num_allocs;
object *x;

void check_win() {
  if(!strcmp(x->flag, "pico")) {
    printf("YOU WIN!!\n");

    char buf[FLAGSIZE_MAX];
    FILE *fd = fopen("flag.txt", "r");
    fgets(buf, FLAGSIZE_MAX, fd);
    printf("%s\n", buf);
    fflush(stdout);

    exit(0);

  } else {
    printf("No flage for u :(\n");
    fflush(stdout);
  }
}

void print_menu() {
    printf("\nHello! Welcome to the challenge!\n");
    fflush(stdout);
}

void init() {

    printf("\nSorry nothing to see here\n");
    fflush(stdout);

    x = malloc(sizeof(object));
    strncpy(x->flag, "bico", 5);
}

void alloc_object() {
    printf("Size of object allocation: ");
    fflush(stdout);
    int size = 0;
    scanf("%d", &size);
    char* alloc = malloc(size);
    printf("Data for flag: ");
    fflush(stdout);
    scanf("%s", alloc);
}

void free_memory() {
    free(x);
}

void print_heap() {
    printf("Nope, nothing to see here\n");
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
            alloc_object();
            break;
        case 3:
            printf("\n\nx = %s\n\n", x->flag);
            fflush(stdout);
            break;
        case 4:
            check_win();
            break;
        case 5:
            free_memory();
            break;
        case 6:
            return 0;
        default:
            printf("Invalid choice\n");
            fflush(stdout);
        }
    }
}
