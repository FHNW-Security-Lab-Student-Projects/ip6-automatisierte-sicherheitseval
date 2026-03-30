
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char input[9]; // 8 Zeichen + Nullbyte
    printf("Enter password: ");
    fgets(input, 9, stdin);

    // Wir entfernen das Newline-Zeichen falls vorhanden
    input[strcspn(input, "\n")] = 0;

    if (strlen(input) != 8) {
        printf("Access denied!\n");
        return 1;
    }

    // Hier ist die magische Prüfung:
    // Der Code wandelt die ersten 4 Bytes in einen Integer um
    // und die nächsten 4 Bytes in einen anderen Integer.
    int part1 = *(int*)(input);
    int part2 = *(int*)(input + 4);
    printf("Debug: part1 = 0x%08x, part2 = 0x%08x\n", part1, part2);

    // Bedingung: (part1 * 31337) + (part2 * 1337) == 0x1337BEEF
    if ((part1 * 31337) + (part2 * 1337) == 0x1337BEEF) {
        printf("Access granted!\n");
        return 0;
    } else {
        printf("Access denied!\n");
        return 1;
    }
}