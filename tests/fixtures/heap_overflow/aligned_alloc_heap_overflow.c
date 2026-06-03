#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    char buffer[32];
    int secret_key;
} SecureData;

int main() {
    size_t size = sizeof(SecureData);
    size_t alignment = 32;

    size_t alloc_size = 64; 

    SecureData *data = (SecureData *)aligned_alloc(alignment, alloc_size);

    if (data == NULL) {
        perror("aligned_alloc failed");
        return 1;
    }

    data->secret_key = 0xDEADBEEF;
    memset(data->buffer, 0, sizeof(data->buffer));

    printf("Allocated %zu bytes at address %p\n", alloc_size, (void*)data);
    printf("Address is aligned: %s\n", (((uintptr_t)data % alignment) == 0) ? "YES" : "NO");
    printf("Secret Key before: 0x%X\n", data->secret_key);

    printf("Enter data (max 32 chars safe, more causes overflow): ");
    
    char input[110];
    if (fgets(input, sizeof(input), stdin) != NULL) {
        input[strcspn(input, "\n")] = 0;
        
        strcpy(data->buffer, input);
    }

    printf("Secret Key after: 0x%X\n", data->secret_key);

    if (data->secret_key != 0xDEADBEEF) {
        printf("CRITICAL: Secret Key corrupted! Heap Overflow detected.\n");
        return 1;
    } else {
        printf("Secret Key intact.\n");
    }

    free(data);
    return 0;
}