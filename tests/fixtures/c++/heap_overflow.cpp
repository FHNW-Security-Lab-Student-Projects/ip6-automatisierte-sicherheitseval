#include <iostream>
#include <cstring>
#include <cstdlib>

class User {
public:
    char name[16];
    bool is_admin;

    User() {
        is_admin = false;
    }
};

void process_input(char *input) {
    User *u = new User[1]; 
    
    strcpy(u[0].name, input);

    if (u[0].is_admin) {
        std::cout << "ACCESS GRANTED (Admin bypassed via Heap Overflow!)" << std::endl;
    } else {
        std::cout << "Access denied." << std::endl;
    }

    // C++ way to free
    delete[] u;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <input>" << std::endl;
        return 1;
    }
    process_input(argv[1]);
    return 0;
}