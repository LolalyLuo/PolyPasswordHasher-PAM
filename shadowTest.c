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
void print_context(const pph_context *context);
int main() {
        PPH_ERROR error;
	pph_context *context;
  	printf("1. initial context\n");

	context = pph_init_context(1,2);
	if (context == NULL){
		printf("can't initialize context\n");
		exit(1);
	}

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
	//printf("%d\n", error);
	//tested store accounts in shadow and delete accounts from context
	store_accounts_shadow(context);
	printf("---------------print original context-----------------\n");
	print_context(context);
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
	printf("---------------print reload context-----------------\n");
	print_context(reload_context);
	error = pph_check_login(reload_context, "David", strlen("David"),
                       "456",strlen("456"));
	if (error == 0) {
		printf("LOGIN SUCCESSFULLY!!!\n");
	}else{
		printf("YOU FAILEDDDDD!!!error: %d \n", error);
	}
} 

void print_context(const pph_context *context){
	printf("context content: threshold: %d isolated_check_bits: %d is_normal_operation: %d \n ", context->threshold, context->isolated_check_bits, context->is_normal_operation);
	const int icb_length = context->isolated_check_bits;
	pph_account_node *search = context->account_data;
	while(search!=NULL){
		int i;
		char result[1000] = "\0";
		pph_entry *entry_node = search->account.entries;
printf("name: %s, number_of_entries: %d\n", search->account.username, search->account.number_of_entries); 
		while(entry_node != NULL){
			char buffer[150];
			char hexsalt[2*MAX_SALT_LENGTH + 1] = "\0";
			char hexsxorh[2*DIGEST_LENGTH + 1] = "\0";
			char hexicb[2*DIGEST_LENGTH + 1] = "\0";
printf("share #: %d\n", entry_node->share_number);
			for (i = 0; i < MAX_SALT_LENGTH; i++) {
				sprintf(buffer, "%0x", entry_node->salt[i]);
				strcat(hexsalt, buffer);
			}
			hexsalt[2 * MAX_SALT_LENGTH+1] = '\0';
printf("hexsalt: %s\n", hexsalt);
			for (i = 0; i < DIGEST_LENGTH; i++) {
				sprintf(buffer, "%0x", entry_node->sharexorhash[i]);
				strcat(hexsxorh, buffer);
			}
			hexsxorh[2 * DIGEST_LENGTH+1] = '\0';
printf("hexsxorh: %s\n", hexsxorh);
			for (i = 0; i < icb_length; i++) {
				sprintf(buffer, "%0x", entry_node->isolated_check_bits[i]);
				strcat(hexicb, buffer);
			}
			hexicb[2 * icb_length+1] = '\0';
printf("hexicb: %s\n\n", hexicb);
			entry_node = entry_node->next;
		}
	search = search->next;
	}
printf("---------------print is over-----------------\n");
}

void load_accounts_shadow(pph_context *context){
	char buffer[4096];
	char name[MAX_USERNAME_LENGTH];
	char password[525];
	char others[125];
	const char s[2] = "$";
	char *token;
	FILE *shadow;
	shadow = fopen("/etc/shadow", "r");
	if (shadow == NULL){
		exit(1);
	}
context->account_data = NULL;
	
	while(fgets(buffer, sizeof buffer, shadow) != NULL){
		sscanf(buffer, "%128[^:]:%525[^:]:%s\n", name, password, others);
		token = strtok(password, s);
		if (strcmp(token, "PPH") == 0){
printf("IT IS A PPH ACCOUT\n");
printf("name->%s, password->%s, other->%s\n", name, password, others);
			//add a new account node to hold data
			pph_account_node *current_node = malloc(sizeof(pph_account_node));
current_node->account.entries = NULL;
			//set up data for that account 
			strcpy(current_node->account.username, name);
			current_node->account.username_length = strlen(name);
			//use a while loop to put entry data in the new node
			int count_entries = 0;
			token = strtok(NULL, s);
			while (token != NULL){
				pph_entry *current_entry = malloc(sizeof(pph_entry));
				//store data in the new entry node
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
				//stored the finished node into the current node
				pph_entry *temp_entry = current_node->account.entries;
				current_node->account.entries = current_entry;
				current_entry->next = temp_entry;
				count_entries++;
			}
			current_node->account.number_of_entries = count_entries;
			//all the data has been stored, now put the node into context
			pph_account_node *temp_node = context->account_data;
			context->account_data = current_node;
			current_node->next = temp_node;
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
	printf("2. store account is called\n");
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
printf("if putting in shadow success: %d \n", retval);
		}
		search = search->next;
	}
	fclose(shadow);
	fclose(temp);
	remove("/etc/shadow");
	rename("/etc/temp", "/etc/shadow");
}
