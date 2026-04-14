// tests/fixtures/stack_overflow/mixed_args/src.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void process_request(int user_id, char *input_data, int log_level) {
    char local_buffer[32];
    
    if (log_level > 0) {
        printf("[User %d] Processing request...\n", user_id);
    }
    
    strcpy(local_buffer, input_data);
    
    printf("Request processed successfully.\n");
}

int main(int argc, char **argv) {
    if (argc > 3) {
        int id = atoi(argv[1]);
        char *data = argv[2];
        int level = atoi(argv[3]);
        
        process_request(id, data, level);
    } else {
        printf("Usage: %s <user_id> <input_data> <log_level>\n", argv[0]);
    }
    return 0;
}