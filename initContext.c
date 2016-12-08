#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libpolypasswordhasher.h>
#include "libgfshare.h"
#include "config.h"

struct _gfshare_ctx {
  unsigned int sharecount;
  unsigned int threshold;
  unsigned int size;
  unsigned char* sharenrs;
  unsigned char* buffer;
  unsigned int buffersize;
};

void store_secret(pph_context *context);
void store_share_context(pph_context *context);
int store_accounts_shadow(pph_context *context);
int delete_all_accounts(pph_context *context);
int main() {
        PPH_ERROR error;
	int retval;
	pph_context *context;
  	printf("initial context\n");

	context = pph_init_context(THRESHOLD, ISOLATED_CHECK_BITS);

	//make some account to test with!  
	//make some account to test with!  
	error = pph_create_account(context, "Alice", strlen("Alice"),
                       "123",strlen("123"), 0);
  	//printf("%d\n", error);
	error = pph_create_account(context, "Bob", strlen("Bob"),
                       "234",strlen("234"), 1);
	//printf("%d\n", error);
	error = pph_create_account(context, "Cathy", strlen("Cathy"),
                       "345",strlen("345"), 2);
	//printf("%d\n", error);
	error = pph_create_account(context, "David", strlen("David"),
                       "456",strlen("456"), 3);
	
	//test code ended 
	retval = store_accounts_shadow(context);
        
	store_secret(context);
	store_share_context(context);

	retval = delete_all_accounts(context);
	error = pph_store_context(context, PPH_CONTEXT_FILE);
        if (error != PPH_ERROR_OK){
          printf("can't store context, erorr: %d \n", error);
	}

	pph_destroy_context(context);

} 


void store_secret(pph_context *context){
	FILE* secretfile;
        secretfile = fopen(PPH_SECRET_FILE, "w+");
        if (secretfile == NULL){
          printf("can't save secret!" );
        }else {
          fwrite(context->secret, DIGEST_LENGTH, 1, secretfile);
	}
	fclose(secretfile);
}
void store_share_context(pph_context *context){
	FILE* sharefile;
	sharefile = fopen(PPH_SHARE_FILE, "w+");
        if (sharefile == NULL){
          	printf("can't save share context!" );
        }else {
		fwrite(context->share_context, sizeof(gfshare_ctx), 1, sharefile);
		fwrite(context->share_context->sharenrs, context->share_context->sharecount, 1, sharefile);
		fwrite(context->share_context->buffer, context->share_context->buffersize, 1, sharefile);
	}
	fclose(sharefile);

}


int store_accounts_shadow(pph_context *context) {
	printf("2. store account is called\n");
	pph_account_node *search;
	int buffersize;
	int retval;
	char namebuffer[4096]; 
	search = context->account_data;
	const int icb_length = context->isolated_check_bits;
	//open shadow and a temp file to work with
	FILE *shadow, *temp;
	shadow = fopen("/etc/shadow", "rt+");
	temp = fopen("/etc/temp", "w+");
	if (shadow == NULL ||  temp== NULL){
		return PPH_FILE_ERR;
	}
	//This piece of code will copy over all accounts not within PPH context
	while(fgets(namebuffer, sizeof namebuffer, shadow) != NULL)  {
		pph_account_node *user;
		user = context->account_data;
		bool exist = false;
		while (user != NULL){
			if(strncmp(namebuffer, user->account.username, strlen(user->account.username)) == 0) {
				exist = true;
				break; 
			} else{
				user = user->next;
			}
		}
		if(!exist) {fputs(namebuffer, temp);}
	}
	
	search = context->account_data;
	while(search!=NULL){
		struct spwd *target = getspnam(search->account.username);
		if (target != NULL){
			int i;
			char result[1000] = "$PPH";
			pph_entry *entry_node = search->account.entries;
		
			while(entry_node != NULL){
				char buffer[150];
				char hexsalt[2*MAX_SALT_LENGTH + 1] = "\0";
				char hexsxorh[2*DIGEST_LENGTH + 1] = "\0";
				char hexicb[2*DIGEST_LENGTH + 1] = "\0";
				for (i = 0; i < MAX_SALT_LENGTH; i++) {
					sprintf(buffer, "%02x", entry_node->salt[i]);
					strcat(hexsalt, buffer);
				}
				hexsalt[2 * MAX_SALT_LENGTH+1] = '\0';
		
				for (i = 0; i < DIGEST_LENGTH; i++) {
					sprintf(buffer, "%02x", entry_node->sharexorhash[i]);
					strcat(hexsxorh, buffer);
				}
				hexsxorh[2 * DIGEST_LENGTH+1] = '\0';

				for (i = 0; i < icb_length; i++) {
					sprintf(buffer, "%02x", entry_node->isolated_check_bits[i]);
					strcat(hexicb, buffer);
				}
				hexicb[2 * icb_length+1] = '\0';
				sprintf(buffer,"$%d$%s$%s$%s", entry_node->share_number,
					hexsalt, hexsxorh, hexicb);
				strcat(result, buffer);
				entry_node = entry_node->next;
			}
			
			target->sp_pwdp = result;
			retval = putspent(target, temp);
		}
		search = search->next;
	}
	fclose(shadow);
	fclose(temp);
	remove("/etc/shadow");
	rename("/etc/temp", "/etc/shadow");
	return 0;
}
int delete_all_accounts(pph_context *context){
	pph_account_node *current,*next;
	if(context == NULL){
		exit(1);
	}
	if(context->account_data != NULL){
		next = context->account_data;
		while(next!=NULL){
			current=next;
			next=next->next;
			// free their entry list
			pph_entry *head = current->account.entries;
 			pph_entry *last;
  			last=head;
 			while(head!=NULL) {
    				head=head->next;
    				free(last);
    				last=head;
  			}
			
			free(current); 
			current = NULL;
		}
	}
	context->account_data = NULL;
	return 0;
}

