// tests/fixtures/common/false_positive_trap.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_looking_func(char *input) {
    char dest[32];
    
    // Eine Bedingung, die für einen Menschen immer TRUE ist (wenn input != NULL).
    // Aber für den Solver könnte sie schwer zu berechnen sein, 
    // wenn wir sie in eine komplexe Schleife oder Bit-Magie verpacken.
    // Hier ein einfaches Beispiel, das manchmal Solver verwirrt:
    
    int len = 0;
    // Manuelle strlen-Implementierung, die den Solver verwirren könnte
    // wenn er nicht tief genug analysiert (loop unrolling limit)
    for (int i = 0; i < 1000; i++) {
        if (input[i] == '\0') {
            len = i;
            break;
        }
    }
    
    // Wenn der Solver die Schleife nicht vollständig auflösen kann (weil 1000 Iterationen zu viel sind),
    // weiß er am Ende nicht genau, wie groß 'len' ist.
    // Er denkt vielleicht: "len könnte alles sein."
    
    if (len < 32) {
        strcpy(dest, input); // Der Solver denkt: "Input könnte > 32 sein, da len unbekannt."
        printf("Copied.\n");
    }
}

int main(int argc, char **argv) {
    if (argc > 1) {
        vulnerable_looking_func(argv[1]);
    }
    return 0;
}