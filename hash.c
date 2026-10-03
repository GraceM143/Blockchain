#include "hash.h"

unsigned char* SSHA(const unsigned char* msg, size_t length) {
    //salt values
    unsigned char A = 56;
    unsigned char B = 99;
    unsigned char C = 102;
    unsigned char D = 67;
    unsigned char E = 76;

    //hashing
    for (int i = 0; i < length; i++) {
        for (int round = 0; round < 8; round++) {
            unsigned char g = (B & C) | (C & D);
            unsigned char old_A = A;
            unsigned char old_E = E; 
            
            A = A >> 2;
            C = (A + old_E);
            D = A ^ (B >> 1);
            E = (g + msg[i]);

            A = old_E;
            B = old_A;
        }
    }

    unsigned char* digest = (unsigned char*)malloc(DIGEST_SIZE * sizeof(unsigned char));
    digest[0] = A;
    digest[1] = B;
    digest[2] = C;
    digest[3] = D;
    digest[4] = E;
    return digest;
}

int digest_equal(struct Digest digest1, struct Digest digest2) {
    return ((digest1.hash0 == digest2.hash0) &&
        (digest1.hash1 == digest2.hash1) &&
        (digest1.hash2 == digest2.hash2) &&
        (digest1.hash3 == digest2.hash3) &&
        (digest1.hash4 == digest2.hash4));
}

void printDigest(struct Digest digest) {
    printf("%d %d %d %d %d\n", digest.hash0, digest.hash1, digest.hash2, digest.hash3, digest.hash4);
}