#include <stdlib.h>
#include <string.h>

/*
 * SSHA2 - Simple State Hash Algorithm 2
 * Based on the diagram showing a 5-word state (A, B, C, D, E)
 * compression function with bitwise operations and message addition.
 */

unsigned char* SSHA2(size_t length, const unsigned char* msg) {
    /* Initial state values (similar to SHA-256 constants for structure) */
    unsigned int A = 0x6A09E667;
    unsigned int B = 0xBB67AE85;
    unsigned int C = 0x3C6EF372;
    unsigned int D = 0xA54FF53A;
    unsigned int E = 0x510E527F;

    /* Process message in 64-byte (512-bit) blocks */
    size_t num_blocks = (length + 63) / 64;
    size_t i;

    for (i = 0; i < num_blocks; i++) {
        unsigned int msg_word;
        size_t offset = i * 64;
        size_t block_len = (i == num_blocks - 1) ? (length % 64) : 64;

        /* Use first 4 bytes of each block as the message word */
        if (offset + 4 <= length) {
            memcpy(&msg_word, msg + offset, 4);
        } else {
            /* Pad with zeros if block is incomplete */
            msg_word = 0;
        }

        /* Compression function as shown in diagram:
         * 1. Right-shift A by 2 bits
         * 2. Right-shift B by 1 bit
         * 3. Compute (C & D) | (D & C)
         * 4. XOR the shifted values: (A >> 2) ^ (B >> 1)
         * 5. Add: ((C & D) | (D & C)) + ((A >> 2) ^ (B >> 1)) + msg[i]
         * 6. Update E with the result
         */

        unsigned int shifted_A = A >> 2;
        unsigned int shifted_B = B >> 1;
        unsigned int and_result = (C & D) | (D & C);
        unsigned int xor_result = shifted_A ^ shifted_B;

        /* Update E state variable */
        E = and_result + xor_result + msg_word;

        /* Shift state variables for next iteration (rotate) */
        unsigned int temp = A;
        A = B;
        B = C;
        C = D;
        D = E;
        E = temp; /* Rotate: old A becomes new E */
    }

    /* Allocate digest (20 bytes for 5 words * 4 bytes each) */
    unsigned char* digest = (unsigned char*)malloc(20);
    if (digest == NULL) {
        return NULL;
    }

    /* Pack the final state into the digest */
    memcpy(digest, &A, 4);
    memcpy(digest + 4, &B, 4);
    memcpy(digest + 8, &C, 4);
    memcpy(digest + 12, &D, 4);
    memcpy(digest + 16, &E, 4);

    return digest;
}
