#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Helper function to perform a right rotation on a 32-bit integer
static uint32_t rotate_right(uint32_t n, unsigned int count) {
    return (n >> count) | (n << (32 - count));
}

// SSHA2 Hash Function
// Parameters:
//   length: The length of the message in bytes
//   msg:    The message to hash
// Returns:
//   A dynamically allocated unsigned char* containing the 20-byte (160-bit) digest.
//   The caller is responsible for freeing the returned memory.
unsigned char* SSHA2(size_t length, const unsigned char* msg) {
    // 1. Initialize State Variables (A, B, C, D, E)
    // Using arbitrary initial values similar to SHA-1/SHA-2 style constants
    uint32_t A = 0x67452301;
    uint32_t B = 0xEFCDAB89;
    uint32_t C = 0x98BADCFE;
    uint32_t D = 0x10325476;
    uint32_t E = 0xC3D2E1F0;

    // 2. Pre-processing: Padding
    // Append bit '1' to the message (8 bits)
    // Append k bits '0' such that length is congruent to 56 (mod 64)
    // Append original length in bits as a 64-bit integer (little-endian)
    
    // Calculate new length after padding
    // Current length in bits
    uint64_t msg_len_bits = (uint64_t)length * 8;
    
    // Number of bytes currently used in the block
    size_t current_block_bytes = length % 64;
    
    // Calculate padding size
    // We need at least 8 bytes for the length, plus 1 byte for the '1' bit marker
    size_t padding_size = 0;
    if (current_block_bytes < 56) {
        padding_size = 56 - current_block_bytes;
    } else {
        padding_size = 64 + 56 - current_block_bytes;
    }
    
    size_t total_len = length + 1 + padding_size + 8;
    
    // Allocate memory for the padded message
    unsigned char* padded_msg = (unsigned char*)malloc(total_len);
    if (!padded_msg) {
        return NULL; // Memory allocation failed
    }
    
    // Copy original message
    memcpy(padded_msg, msg, length);
    
    // Add the '1' bit (0x80)
    padded_msg[length] = 0x80;
    
    // Add zeros
    memset(padded_msg + length + 1, 0, padding_size);
    
    // Add the length in bits (64-bit, little-endian)
    uint64_t len_bits = msg_len_bits;
    for (size_t i = 0; i < 8; i++) {
        padded_msg[total_len - 8 + i] = (unsigned char)(len_bits & 0xFF);
        len_bits >>= 8;
    }
    
    // 3. Process each 512-bit (64-byte) block
    size_t num_blocks = total_len / 64;
    
    for (size_t block_idx = 0; block_idx < num_blocks; block_idx++) {
        // Extract 16 32-bit words from the current 64-byte block
        uint32_t W[16];
        for (int i = 0; i < 16; i++) {
            W[i] = ((uint32_t)padded_msg[block_idx * 64 + i * 4] << 24) |
                   ((uint32_t)padded_msg[block_idx * 64 + i * 4 + 1] << 16) |
                   ((uint32_t)padded_msg[block_idx * 64 + i * 4 + 2] << 8)  |
                   ((uint32_t)padded_msg[block_idx * 64 + i * 4 + 3]);
        }
        
        // 4. Compression Function (One Round per Message Word)
        // The diagram shows a single iteration. We perform 16 iterations per block,
        // one for each 32-bit word W[i].
        
        uint32_t a = A;
        uint32_t b = B;
        uint32_t c = C;
        uint32_t d = D;
        uint32_t e = E;
        
        for (int i = 0; i < 16; i++) {
            // From the diagram:
            // 1. Shift operations: A >> 2, B >> 1
            uint32_t shifted_a = a >> 2;
            uint32_t shifted_b = b >> 1;
            
            // 2. Bitwise XOR: (A >> 2) ^ (B >> 1)
            uint32_t xor_result = shifted_a ^ shifted_b;
            
            // 3. Bitwise AND: (C & D) and (D & E)
            uint32_t and_cd = c & d;
            uint32_t and_de = d & e;
            
            // 4. Bitwise OR: (C & D) | (D & E)
            uint32_t or_result = and_cd | and_de;
            
            // 5. Addition: XOR result + OR result + E + msg[i]
            // Note: Using modular addition (uint32_t overflow handles mod 2^32)
            uint32_t sum = xor_result + or_result + e + W[i];
            
            // 6. Update Register A
            a = sum;
            
            // 7. Rotate Registers: B<-A, C<-B, D<-C, E<-D
            // We need to save the old values before overwriting
            uint32_t old_a = a; // Wait, a is already updated. 
            // Let's re-do the rotation logic carefully.
            // The diagram implies the update happens simultaneously or in a specific sequence.
            // Standard practice: Save old values, then update.
        }
        
        // Let's restart the round logic with proper variable saving
        a = A;
        b = B;
        c = C;
        d = D;
        e = E;
        
        for (int i = 0; i < 16; i++) {
            uint32_t temp_a = a;
            uint32_t temp_b = b;
            uint32_t temp_c = c;
            uint32_t temp_d = d;
            uint32_t temp_e = e;
            
            // Operations from diagram
            uint32_t shifted_a = temp_a >> 2;
            uint32_t shifted_b = temp_b >> 1;
            uint32_t xor_val = shifted_a ^ shifted_b;
            
            uint32_t and_cd = temp_c & temp_d;
            uint32_t and_de = temp_d & temp_e;
            uint32_t or_val = and_cd | and_de;
            
            // New A
            a = xor_val + or_val + temp_e + W[i];
            
            // Rotate others
            b = temp_a;
            c = temp_b;
            d = temp_c;
            e = temp_d;
        }
        
        // 5. Add compressed chunk to current hash value
        A += a;
        B += b;
        C += c;
        D += d;
        E += e;
    }
    
    // 6. Produce the final hash value (digest)
    // The state is A, B, C, D, E (5 * 32 bits = 160 bits = 20 bytes)
    unsigned char* digest = (unsigned char*)malloc(20);
    if (!digest) {
        free(padded_msg);
        return NULL;
    }
    
    // Convert the 32-bit registers to a byte array (Big-Endian order)
    digest[0]  = (A >> 24) & 0xFF;
    digest[1]  = (A >> 16) & 0xFF;
    digest[2]  = (A >> 8) & 0xFF;
    digest[3]  = A & 0xFF;
    
    digest[4]  = (B >> 24) & 0xFF;
    digest[5]  = (B >> 16) & 0xFF;
    digest[6]  = (B >> 8) & 0xFF;
    digest[7]  = B & 0xFF;
    
    digest[8]  = (C >> 24) & 0xFF;
    digest[9]  = (C >> 16) & 0xFF;
    digest[10] = (C >> 8) & 0xFF;
    digest[11] = C & 0xFF;
    
    digest[12] = (D >> 24) & 0xFF;
    digest[13] = (D >> 16) & 0xFF;
    digest[14] = (D >> 8) & 0xFF;
    digest[15] = D & 0xFF;
    
    digest[16] = (E >> 24) & 0xFF;
    digest[17] = (E >> 16) & 0xFF;
    digest[18] = (E >> 8) & 0xFF;
    digest[19] = E & 0xFF;
    
    // Clean up
    free(padded_msg);
    
    return digest;
}
