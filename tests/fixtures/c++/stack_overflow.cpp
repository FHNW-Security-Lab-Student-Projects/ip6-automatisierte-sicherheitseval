#include <iostream>
#include <cstring>
#include <cstdlib>

class Secret {
public:
    char buffer[32];
    int access_code;

    Secret() {
        access_code = 0x12345678;
    }

    void leak() {
        if (access_code != 0x12345678) {
            std::cout << "Secret modified! New code: " << std::hex << access_code << std::endl;
        } else {
            std::cout << "Secret intact." << std::endl;
        }
    }
};

void vulnerable_function(char *input) {
    Secret s;
    
    strcpy(s.buffer, input);

    s.leak();
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <input>" << std::endl;
        return 1;
    }
    vulnerable_function(argv[1]);
    return 0;
}