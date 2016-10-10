#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libpolypasswordhasher.h>
#include "libgfshare.h"
#include "config.h"

void store_accounts(pph_context *context);
int main() {
        PPH_ERROR error;
	pph_context *context;
  	printf("initial context\n");

	context = pph_init_context(2,2);
	if (context == NULL){
		printf("can't initialize context\n");
		exit(1);
	}

	//make some account to test with!  
	error = pph_create_account(context, "abc", strlen("abc"),
                       "123",strlen("123"), 0);
  	printf("%d\n", error);
	error = pph_create_account(context, "abcabc", strlen("abcabc"),
                       "345",strlen("345"), 2);
	printf("%d\n", error);
	error = pph_create_account(context, "theabc", strlen("theabc"),
                       "567",strlen("567"), 1);
	printf("%d\n", error);
	store_accounts(context);
	//test code ended 
	error = pph_store_context(context, "/home/lolaly/PolyPasswordHasher-PAM/PPHdata");
        if (error != PPH_ERROR_OK){
          printf("can't store context, erorr: %d \n", error);
	}
        
	pph_destroy_context(context);
	printf("context is initialed and stored!\n");
} 

void store_accounts(pph_context *context) {
	printf("store_account is called\n");	
	FILE *shadow;
	shadow = fopen("/etc/shadow", "a+");
	if (shadow == NULL){
		exit(1);
	}
	pph_account_node *search;
	int buffersize;
	int retval; 
	search = context->account_data;
	
	while(search!=NULL){
	printf("in first loop\n");
		struct spwd *target = getspnam(search->account.username);
		int i;
		char result[525] = "$PPH";
		pph_entry *entry_node = search->account.entries;
		while(entry_node != NULL){
			char buffer[100];
			char hexsalt[2*MAX_SALT_LENGTH] = "\0";
			char hexsxorh[2*DIGEST_LENGTH] = "\0";
			printf("in second loop\n");
			for (i = 0; i < MAX_SALT_LENGTH; i++) {
				sprintf(buffer, "%0x", entry_node->salt[i]);
				printf("buffer is: %s\n", buffer);
				strcat(hexsalt, buffer);
				printf("hexsalt is: %s\n", hexsalt);
			}
			printf("salt is: %s\n", hexsalt);
			for (i = 0; i < DIGEST_LENGTH; i++) {
				sprintf(buffer, "%0x", entry_node->sharexorhash[i]);
				printf("buffer is: %s\n", buffer);
				strcat(hexsxorh, buffer);
				printf("hexsxorh is: %s\n", hexsxorh);
			}
			//sprintf(buffer, "%d", 32);
			sprintf(buffer,"$%d$%s$%s", entry_node->share_number,
				hexsalt, hexsxorh);
			printf("HEXSXORH is: %s\n", hexsxorh);
			printf("HEXSALT is: %s\n", hexsalt);
			strcat(result, buffer);
			
			printf("result is: %s\n", result);
			entry_node = entry_node->next;
		}
		
		//target->sp_pwdp = buffer;
		//retval = putspent(target, shadow);
		search = search->next;
	}
	fclose(shadow);
}
