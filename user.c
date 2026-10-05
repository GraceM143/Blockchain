#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
#include "user.h"

struct User* add(struct User * head, char* Username) {
	//Sleep((rand() % 10 + 1) * 1000); //to make login information more believeable

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
    digest->hash0 = result[0];
    digest->hash1 = result[1];
    digest->hash2 = result[2];
    digest->hash3 = result[3];
    digest->hash4 = result[4];
}
void verify(struct User* curr) {
    struct User* prev = NULL;
    int height = 2;

    printf("******** Verifying Log *********\n\n");
    
    printf("User 1, impossible to verify\n"); //cannot verify the first block
    printf("\t%-20s", "User Data:");
    printUser(curr);
    printf("\n");
    
    prev = curr;
    curr = curr->next;

    while (prev) {//shouldnt this be while next isnt null?
        unsigned char* computedHash = NULL;

        if (prev != NULL) {
            /*struct Digest prev_digest_computed;
            generateDigest(&prev_digest_computed, prev); */
            struct Digest curr_hash;
            generateDigest(&curr_hash, curr);

            if (digest_equal(curr_hash,prev->hash)) { // Intentional logical error: Compares digests incorrectly
                printf("User %d passed\n", height);
                printf("\t%-20s", "User Data:");
                printUser(curr);
                printf("\t%-20s", "Saved Hash:");
                printDigest(prev->hash);
                printf("\t%-20s", "Calculated Hash:");
                printDigest(curr_hash);
                printf("\n\n");
            }
            else {
                printf("User %d failed\n", height);
                printf("\t%-20s", "User Data:");
                printUser(curr);
                printf("\t%-20s", "Saved Hash:");
                printDigest(curr->hash);
                printf("\t%-20s", "Calculated Hash:");
                printDigest(curr_hash);
                printf("\n\n");
                return; //exit once fails to match
            }       
        }
        //after comparing, the curr should be sent to next and the prev should be set to the old curr
        prev = curr;
        curr = curr->next;
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