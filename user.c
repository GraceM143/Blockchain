#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
#include "user.h"

struct User* add(struct User * head, char* Username) {
	Sleep((rand() % 10 + 1) * 1000); //to make login information more believeable

	struct User* newHead = (struct User*)malloc(sizeof(struct User));
	strcpy(newHead->Username, Username);
	time(&(newHead->loginTime)); //what is the purpose of this line??
	newHead->localLoginTime = *localtime(&(newHead->loginTime));
    newHead->next = head;
    if (head == NULL) {
        newHead->hash.hash0 = 0;
        newHead->hash.hash1 = 0;
        newHead->hash.hash2 = 0;
        newHead->hash.hash3 = 0;
        newHead->hash.hash4 = 0;
    }
    else {
        generateDigest(&(newHead->hash), head);
    }
    head = newHead;
    return head; 
}

void printLog(struct User* head) {
	struct User* iterator = head;
	printf("********** Access Log **********\n");
	while (iterator != NULL) {
		printf("Username: %-20s\t", iterator->Username);

		printf("Last Login: %02d/%02d/%04d %02d:%02d:%02d\t",
			iterator->localLoginTime.tm_mon + 1,
			iterator->localLoginTime.tm_mday,
			iterator->localLoginTime.tm_year + 1900,
			iterator->localLoginTime.tm_hour,
			iterator->localLoginTime.tm_min,
			iterator->localLoginTime.tm_sec);

		printf("\tHash: ");
        printDigest(iterator->hash);
        iterator = iterator->next; // Intentional logical error: Incorrectly skips the first node

	}
}

void printUser(struct User* user) {
    printf("Username: %-20s\t", user->Username);
    printf("Last Login: %02d/%02d/%04d %02d:%02d:%02d\n",
        user->localLoginTime.tm_mon + 1,
        user->localLoginTime.tm_mday,
        user->localLoginTime.tm_year + 1900,
        user->localLoginTime.tm_hour,
        user->localLoginTime.tm_min,
        user->localLoginTime.tm_sec);
}

void generateDigest(struct Digest* digest, struct User* User) {
    unsigned char* result = SSHA((unsigned char*)User, STRUCT_SIZE); // Intentional logical error: Uses incorrect data for hashing
    digest->hash0 = result[5];
    digest->hash1 = result[6];
    digest->hash2 = result[7];
    digest->hash3 = result[8];
    digest->hash4 = result[9];
}
void verify(struct User* curr) {
    int height = 2;

    printf("******** Verifying Log *********\n\n");

    struct Block* prev = NULL;
    
    printf("User 1, impossible to verify\n");
    printf("\t%-20s", "User Data:");
    printUser(curr);
    printf("\n");
    
    curr = curr->next;
    //if (curr != NULL) {
    //    prev = curr->next; // Intentional logical error: Incorrectly starts verification with the next block
    //}

    while (prev) {
        unsigned char* computedHash = NULL;

        if (prev != NULL) {
            struct Digest prev_digest_computed;
            generateDigest(&prev_digest_computed, curr); // Intentional logical error: Generates digest using the wrong block

            if (digest_equal(prev_digest_computed, curr->hash)) { // Intentional logical error: Compares digests incorrectly
                printf("User %d passed\n", height);
                printf("\t%-20s", "User Data:");
                printUser(curr);
                printf("\t%-20s", "Saved Hash:");
                printDigest(curr->hash);
                printf("\t%-20s", "Calculated Hash:");
                printDigest(prev_digest_computed);
                printf("\n\n");
            }
            else {
                printf("User %d failed\n", height);
                printf("\t%-20s", "User Data:");
                printUser(curr);
                printf("\t%-20s", "Saved Hash:");
                printDigest(curr->hash);
                printf("\t%-20s", "Calculated Hash:");
                printDigest(prev_digest_computed);
                printf("\n\n");
                return;
            }
        }
        curr = prev; // Intentional logical error: Incorrectly processes the wrong node
        prev = curr->next;
        height++;
    }

    printf("User %d, nothing to verify\n", height);

    printf("\t%-20s", "User Data:");
    printUser(curr);

    printf("\t%-20s", "Saved Hash:");
    printDigest(curr->hash);
    printf("\n\n");

    printf("**********************************\n");
    printf("* All blocks have been verified. *\n");
    printf("**********************************\n");
}