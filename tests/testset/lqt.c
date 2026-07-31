#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

void winner()
{
  printf("that wasn't too bad now, was it? @ %d\n", time(NULL));
}

int main(int argc, char **argv)
{
  char *a, *b, *c;

  a = malloc(32);
  b = malloc(32);
  c = malloc(32);

  strncpy(a, argv[1], 32 - 1);
  strncpy(b, argv[2], 32 - 1);
  strncpy(c, argv[3], 32 - 1);

  free(c);
  free(b);
  free(a);

  printf("dynamite failed?\n");
}