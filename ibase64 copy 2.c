#ifndef BASE46_H
#define BASE46_H

#include <stdlib.h>
#include <memory.h>
#include <stdio.h>
#include <string.h>


/***********************************************
Encodes ASCCI string into base64 format string
@param plain ASCII string to be encoded
@return encoded base64 format string
***********************************************/
int encode(unsigned char* plain, unsigned char* cipher);


/***********************************************
decodes base64 format string into ASCCI string
@param plain encoded base64 format string
@return ASCII string to be encoded
***********************************************/
char* decode(char* cipher);


#endif //BASE46_H
char base46_map[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                     'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                     'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                     'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

int get_map(char num, unsigned char* cipher, int c){
    char x = base46_map[num];
    if(x == 'x'){
        cipher[c++]='x';
        cipher[c++]='1';
    }
    else if(x == '+'){
        cipher[c++]='x';
        cipher[c++]='2';
    }
    else if(x == '/'){
        cipher[c++]='x';
        cipher[c++]='3';
    }
    else{
        cipher[c++]=x;
    }
    return c;
}

int encode(unsigned char* plain, unsigned char* cipher) {

    char counts = 0;
    char buffer[3];
    //char* cipher = malloc(strlen(plain) * 4 / 3 + 4);
    int i = 0, c = 0;

    for(i = 0; plain[i] != '\0'; i++) {
        buffer[counts++] = plain[i];
        if(counts == 3) {
            c = get_map(buffer[0] >> 2, cipher, c);
            c = get_map(((buffer[0] & 0x03) << 4) + (buffer[1] >> 4), cipher, c);
            c = get_map(((buffer[1] & 0x0f) << 2) + (buffer[2] >> 6), cipher, c);
            c = get_map(buffer[2] & 0x3f, cipher, c);
            counts = 0;
        }
    }

    if(counts > 0) {
        c = get_map(buffer[0] >> 2, cipher, c);
        if(counts == 1) {
            c = get_map((buffer[0] & 0x03) << 4, cipher, c);
            cipher[c++] = 'x';
            cipher[c++] = '4';
        } else {                      // if counts == 2
            c = get_map(((buffer[0] & 0x03) << 4) + (buffer[1] >> 4), cipher, c);
            c = get_map((buffer[1] & 0x0f) << 2, cipher, c);
        }
        cipher[c++] = 'x';
        cipher[c++] = '4';
    }

    cipher[c] = '\0';   /* string padding character */
    return c;
}


/*char* decode(char* cipher) {

    char counts = 0;
    char buffer[4];
    char* plain = malloc(strlen(cipher) * 3 / 4);
    int i = 0, p = 0;

    for(i = 0; cipher[i] != '\0'; i++) {
        char k;
        for(k = 0 ; k < 64 && c = get_map(k) != cipher[i]; k++);
        buffer[counts++] = k;
        if(counts == 4) {
            plain[p++] = (buffer[0] << 2) + (buffer[1] >> 4);
            if(buffer[2] != 64)
                plain[p++] = (buffer[1] << 4) + (buffer[2] >> 2);
            if(buffer[3] != 64)
                plain[p++] = (buffer[2] << 6) + buffer[3];
            counts = 0;
        }
    }

    plain[p] = '\0';    //string padding character
    return plain;
}*/