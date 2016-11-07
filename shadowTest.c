#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libpolypasswordhasher.h>
#include "libgfshare.h"
#include "config.h"

void store_accounts_shadow(pph_context *context);
void delete_all_accounts(pph_context *context);
void load_accounts_shadow(pph_context *context);
int main() {
        PPH_ERROR error;
	pph_context *context;
  	printf("initial context\n");

	context = pph_init_context(1,2);
	if (context == NULL){
		printf("can't initialize context\n");
		exit(1);
	}

	//make some account to test with!  
	error = pph_create_account(context, "shadowabc", strlen("shadowabc"),
                       "123",strlen("123"), 0);
  	printf("%d\n", error);
	error = pph_create_account(context, "shadowabcabc", strlen("shadowabcabc"),
                       "345",strlen("345"), 3);
	printf("%d\n", error);
	error = pph_create_account(context, "shadowtheabc", strlen("shadowtheabc"),
                       "567",strlen("567"), 1);
	printf("%d\n", error);
	error = pph_create_account(context, "marry", strlen("marry"),
                       "567",strlen("567"), 1);
	printf("%d\n", error);
	//tested store accounts in shadow and delete accounts from context
	store_accounts_shadow(context);
	delete_all_accounts(context);
	error = pph_store_context(context, "/home/lolaly/PolyPasswordHasher-PAM/PPHdata");
        if (error != PPH_ERROR_OK){
          printf("can't store context, erorr: %d \n", error);
	}
	pph_destroy_context(context);
	printf("context is initialed and stored!\n");

	//Now reload the context and reload all the accounts
	pph_context* reload_context = pph_reload_context("/home/lolaly/PolyPasswordHasher-PAM/PPHdata");
	if (reload_context == NULL){
		printf("error loading context\n");
	}
	printf("PPH context re---loaded\n");
	load_accounts_shadow(reload_context);
	error = pph_check_login(reload_context, "shadowabc", strlen("shadowabc"),
                       "123",strlen("123"));
	if (error == 0) {
		printf("YEAH!!!! LOGIN SUCCESSFULLY!!!\n");
	}else{
		printf("YOU FAILEDDDDD!!!error: %d \n", error);
	}
} 



void load_accounts_shadow(pph_context *context){
	char buffer[4096];
	char name[MAX_USERNAME_LENGTH];
	char password[525];
	char others[125];
	const char s[2] = "$";
	char *token;
	char *hexsalt;//[MAX_SALT_LENGTH*2 +1] = "\0";
	char *hexsxorh;//[DIGEST_LENGTH*2 +1] = "\0";
	char *hexicb;//[DIGEST_LENGTH*2 +1] = "\0";
	int sharenum;
	FILE *shadow;
	shadow = fopen("/etc/shadow", "rt+");
	if (shadow == NULL){
		exit(1);
	}
	
	while(fgets(buffer, sizeof buffer, shadow) != NULL){
		//fgets(buffer, 4096, shadow);
		sscanf(buffer, "%128[^:]:%525[^:]:%s\n", name, password, others);
		//printf("name->%s, password->%s, other->%s\n\n\n", name, password, others);
		token = strtok(password, s);
		if (strcmp(token, "PPH") == 0){
			//printf("IT IS A PPH ACCOUT\n");
			//add a new account into context to hold the PPH account 
			pph_account_node *current_node = malloc(sizeof(pph_account_node));
			pph_account_node *temp_node = context->account_data;
			context->account_data = current_node;
			current_node->next = temp_node;
			//set up data for that account 
			strcpy(current_node->account.username, name);
			current_node->account.username_length = strlen(name);
			//use a while loop to put data in entry
			int count_entries = 0;
			token = strtok(NULL, s);
			while (token != NULL){
				pph_entry *current_entry = malloc(sizeof(pph_entry));
				pph_entry *temp_entry = current_node->account.entries;
				current_node->account.entries = current_entry;
				current_entry->next = temp_entry;
				//store data in
				//storing share_number 
				current_entry->share_number = atoi(token);
				//storing salt
				token = strtok(NULL, s);
				for (int i = 0; i < strlen(token); i++){
					sscanf(token+(i*2), "%02x", &current_entry->salt[i]);
				}
				current_entry->salt_length = strlen(current_entry->salt);
				//store shore_xor_hash
				token = strtok(NULL, s);
				for (int i = 0; i < strlen(token); i++){
					sscanf(token+(i*2), "%02x", &current_entry->sharexorhash[i]);
				}
				//store isolated check bits
				token = strtok(NULL, s);
				for (int i = 0; i < strlen(token); i++){
					sscanf(token+(i*2), "%02x", &current_entry->isolated_check_bits[i]);
				}
				//before go back to the loop, increase count and read another token 
				token = strtok(NULL, s);
				count_entries++;
			}
			current_node->account.number_of_entries = count_entries;
		}
	}
	fclose(shadow);
}
void delete_all_accounts(pph_context *context){
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
}

void store_accounts_shadow(pph_context *context) {
	printf("store account is called\n");
	pph_account_node *search;
	int buffersize;
	int retval;
	char namebuffer[4096]; 
	search = context->account_data;
	const int icb_length = context->isolated_check_bits;
	
	FILE *shadow, *temp;
	shadow = fopen("/etc/shadow", "rt+");
	temp = fopen("/etc/temp", "w+");
	if (shadow == NULL ||  temp== NULL){
		printf("USE SUDO!!!!\n");
		exit(1);
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
					sprintf(buffer, "%0x", entry_node->salt[i]);
					strcat(hexsalt, buffer);
				}
				hexsalt[2 * MAX_SALT_LENGTH+1] = '\0';
		
				for (i = 0; i < DIGEST_LENGTH; i++) {
					sprintf(buffer, "%0x", entry_node->sharexorhash[i]);
					strcat(hexsxorh, buffer);
				}
				hexsxorh[2 * DIGEST_LENGTH+1] = '\0';

				for (i = 0; i < icb_length; i++) {
					sprintf(buffer, "%0x", entry_node->isolated_check_bits[i]);
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
}
