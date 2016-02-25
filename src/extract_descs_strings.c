#include <stdio.h>
#include "descs_strings.h"

/*
 * Writing descriptors and strings to binary file
 */

int main() {

    int ret;
    FILE *descs, *strings;

    /* open file for descriptors */
    descs = fopen("descs","w");
    if (!descs){
        perror("could not open file with descriptors");
        return -1;
    }

    /* open file for strings */
    strings = fopen("strings", "w");
    if (!strings) {
        perror("could not open file with strings");
        return -1;
    }

    /* write descriptors to file */
    ret = fwrite(&descriptors, sizeof(descriptors), 1, descs);
    if (ret < 0) {
        perror("could not write descriptors");	
        return -1;
    }

    /* write strings to file */
    ret = fwrite(&strings, sizeof(strings), 1, strings);
    if(ret < 0) {
       perror("could not write strings");
       return -1;
    }

    fclose(descs);
    fclose(strings);

    return 0;
}

