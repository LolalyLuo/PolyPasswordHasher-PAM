#include "config.h"
#include<sys/types.h>
#include<sys/stat.h>
#include<unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define PAM_SM_PASSWORD
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#include <syslog.h>
#include <errno.h>
#include <shadow.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <libpolypasswordhasher.h>
#include "libgfshare.h"
#define MAX_PASSWD_TRIES 3

struct _gfshare_ctx {
  unsigned int sharecount;
  unsigned int threshold;
  unsigned int size;
  unsigned char* sharenrs;
  unsigned char* buffer;
  unsigned int buffersize;
};

void get_secret(pph_context *context);
void get_share_context(pph_context *context);
void store_secret(pam_handle_t *pamh, pph_context *context);
void store_share_context(pam_handle_t *pamh, pph_context *context);
void store_account(pam_handle_t *pamh, const char* username, const char* password);
void unlock_context(pam_handle_t *pamh, pph_context *context);
int mount_ram(const char* theFile);

int store_accounts_shadow(pph_context *context);
int delete_all_accounts(pph_context *context);
int load_accounts_shadow(pph_context *context);

PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	pam_syslog(pamh, LOG_NOTICE, "PPH: Set credenticial successed!\n");
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	pam_syslog(pamh, LOG_NOTICE, "PPH: Account management successed!\n");
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char *argv[]){
	pam_syslog(pamh, LOG_NOTICE, "PPH: Open session successed!\n");
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char *argv[]){
	pam_syslog(pamh, LOG_NOTICE, "PPH: Close session successed!\n");
	return PAM_SUCCESS;
}

//authentication 
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {

	int retval;
	int error = -1;
	const char* username;
	const char* password;
	int retry = 0;
	pph_context *context;
	
	pph_account_node *search;
	pph_account_node *target = NULL;
	uint8 sharenumber;
	//return PAM_SUCCESS;
	pam_syslog(pamh, LOG_INFO, "PPH: pam_sm_authenticate is being called. \n");
	
	//load context
	context =  pph_reload_context(PPH_CONTEXT_FILE);
	if (context == NULL){
		pam_syslog(pamh, LOG_ERR, "PPH: Can't open context\n");
		return PAM_AUTHINFO_UNAVAIL;
	}
	if (context->account_data == NULL){
		retval = load_accounts_shadow(context);
		if (retval != 0){
			pam_syslog(pamh, LOG_ERR, "PPH: Can't load accounts from shadow. \n");
			return PAM_AUTHINFO_UNAVAIL;
		}
	}
	pam_syslog(pamh, LOG_INFO, "PPH: context & accounts are loaded. \n");
	

	context->is_normal_operation = false;
	//load secret and share context if available. 
	get_secret(context);
	get_share_context(context);
	//if both secret and share context are available, finish bootstraping		
	if (context->secret != NULL && context->share_context != NULL) {
		context->is_normal_operation = true;
		pam_syslog(pamh, LOG_ERR,"Both secret and share context are now available\n");
	}

	//authenticate the user with PPH
	//get username from user
	retval = pam_get_user(pamh, &username, "username(pph_pam): ");	
	if (retval != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR, "PPH: can't access username. \n");
		return retval;
	}
	//get password from userr
	retval = pam_get_authtok(pamh, PAM_AUTHTOK, &password, "password(pph_pam): ");
	if (retval != PAM_SUCCESS){
		pam_syslog(pamh, LOG_ERR, "PPH: can't get password. \n");
		return retval;
	}

	//try to authenticate the user with PPH database
	error = pph_check_login(context, username, strlen(username), password, strlen(password));
	
	//return the correct message for the user 
	if (error == PPH_ERROR_OK){
		pam_syslog(pamh, LOG_INFO, "PPH: Authenticate user successfully \n");
	}else if (error == PPH_ACCOUNT_IS_INVALID){
		pam_syslog(pamh, LOG_INFO, "PPH: Either username or password is incorrect \n");
	}else {
		pam_syslog(pamh, LOG_INFO, "PPH: Fail to authenticate the user for other errors \n");
	}
	

	//If the account authenticated is a protector account, put it into a file for bootstrapping purpose
	if (error == PPH_ERROR_OK && context->is_normal_operation == false){
		search = context->account_data;
		while(search!=NULL){
			// we check lengths first and then compare what's in it. 
			if(strlen(username) == search->account.username_length && 
		          !memcmp(search->account.username,username,strlen(username))){
			target = search;
			break;
   			}
   		search=search->next;
  		}	
		sharenumber = target->account.entries->share_number;
		if (sharenumber != SHIELDED_ACCOUNT && sharenumber != BOOTSTRAP_ACCOUNT){
			store_account(pamh,username, password);
			//after storing account, try to use it to unlock the context and save secret and share context in files
			unlock_context(pamh, context);
		}
	}

	
	//after authentication, destroy the context we used
	if (pph_destroy_context(context) != PPH_ERROR_OK){
		pam_syslog(pamh, LOG_ERR, "PPH: Can't destroy context\n");
	}
	
	//lastly, return correct value
	if (error == PPH_ERROR_OK){
		return PAM_SUCCESS;
	}else {
		return PAM_AUTH_ERR;
	}
}	


	



//change password
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv){
	int retval, error;
	const char *username;
	const char *password;
	pph_context *context;

	pam_syslog(pamh, LOG_INFO, "PPH: pam_sm_chauthtok is being called. \n");
	//get the username from user
	retval = pam_get_user(pamh, &username, NULL);
	if (retval != PAM_SUCCESS){
		pam_syslog(pamh, LOG_ERR, "PPH: Trouble getting username \n");
		return retval;
	}
	//get the new password from user
	retval = pam_get_authtok(pamh, PAM_AUTHTOK, &password, "NEW password: ");
	if (retval != PAM_SUCCESS){
		pam_syslog(pamh, LOG_ERR, "PPH: Can't get password \n");
		return retval;
	}

	//check prelim at first call, which is if the context is loaded successfully
 	if (flags == PAM_PRELIM_CHECK) {
		pam_syslog(pamh, LOG_INFO,"pam prelim checking\n");
		return PAM_SUCCESS;
	}

	//if it is not prelim check, load context to get ready to change password 
	context =  pph_reload_context(PPH_CONTEXT_FILE);
	if (context == NULL){
		pam_syslog(pamh, LOG_ERR, "PPH: Can't open context\n");
		return PAM_AUTHTOK_LOCK_BUSY;
	}
	if (context->account_data == NULL){
		retval = load_accounts_shadow(context);
		if (retval != 0){
			pam_syslog(pamh, LOG_ERR, "PPH: Can't load accounts from shadow. \n");
			return PAM_AUTHTOK_LOCK_BUSY;
		}
	}
	pam_syslog(pamh, LOG_INFO, "PPH: context & accounts are loaded. \n");
	
	context->is_normal_operation = false;
	//load secret and share context if available. 
	get_secret(context);
	get_share_context(context);
	//if the secret and share are still not available, try to unlock them		
	if (context->secret != NULL && context->share_context != NULL) {
		context->is_normal_operation = true;
		pam_syslog(pamh, LOG_ERR,"Both secret and share context are now available\n");
	}


	//try to use the user name and password to create a user
	error = pph_create_account(context, username, strlen(username), password, strlen(password), 0);
	if (error == PPH_ERROR_OK) {
		pam_syslog(pamh, LOG_INFO, "PPH: created a new user with new password successfully!\n");
	} else if (error == PPH_ACCOUNT_EXISTS) {
		error = pph_change_password(context, username, strlen(username), password, strlen(password));
		if (error == PPH_ERROR_OK) {
			pam_syslog(pamh, LOG_INFO, "PPH: changed password successfully!\n");
		}
	} else {
		pam_syslog(pamh, LOG_ERR, "PPH: Can't change password currently %d \n", error);	
	}
	//up to here we can store and destroy context
	//if (pph_store_context(context, PPH_CONTEXT_FILE) != PPH_ERROR_OK){
	//	pam_syslog(pamh, LOG_ERR, "PPH: Can't store context %d \n", error);
	//}
	retval = store_accounts_shadow(context);
	if (retval != 0){
		pam_syslog(pamh, LOG_ERR, "PPH: Can't store accounts in shadow %d \n", error);	
		return PAM_AUTH_ERR;
	}
	if (pph_destroy_context(context) != PPH_ERROR_OK){
		pam_syslog(pamh, LOG_ERR, "PPH: Can't destroy context %d \n", error);
	}

	//lastly, return the right PAM value
	if (error == PPH_ERROR_OK) {
		return PAM_SUCCESS;
	} else {
		return 	PAM_AUTH_ERR;
	}
	
}


void get_secret(pph_context *context){
	FILE *secretfile;
	secretfile = fopen(PPH_SECRET_FILE, "r");
	if (secretfile == NULL) {
 		return;
	}
	context->secret=malloc(sizeof(*context->secret)*DIGEST_LENGTH);
  	if(context->secret == NULL){
    		return;
  	}
	fread(context->secret, DIGEST_LENGTH, 1, secretfile);
	context->AES_key = context->secret;
	printf("end of getting secret\n");
	fclose(secretfile);
}

void get_share_context(pph_context *context) {
	FILE *sharefile;
	sharefile = fopen(PPH_SHARE_FILE, "r");
	if (sharefile == NULL) {
 		return;
	}
	context->share_context = malloc(sizeof(gfshare_ctx));
	fread(context->share_context, sizeof(gfshare_ctx), 1, sharefile);
	context->share_context->sharenrs =  malloc(context->share_context->sharecount);
	fread(context->share_context->sharenrs, context->share_context->sharecount, 1, sharefile);
	context->share_context->buffer = malloc(context->share_context->buffersize);
	fread(context->share_context->buffer, context->share_context->buffersize, 1, sharefile);
	fclose(sharefile);
}

void store_account(pam_handle_t *pamh, const char* username, const char* password){
	FILE *accountfile;
	int error = mount_ram(PPH_RAMDISK);
	if(error){
		pam_syslog(pamh, LOG_ERR, "PPH: Error saving account information%d \n", error);
		return;
	}		
	//make/open file in the mounted folder
	char pph_account_file[MAX_PATH_LENGTH];
	if (strlen(PPH_RAMDISK) > (MAX_PATH_LENGTH - 10)){
		pam_syslog(pamh, LOG_ERR, "PPH: Path of the ramdisk is too long%d \n", error);
		return;
	}
	strcpy(pph_account_file, PPH_RAMDISK);
	strcat(pph_account_file, "account");
	accountfile = fopen(pph_account_file, "a");
	if (accountfile == NULL) {
 		return;
	}
	printf("saving account data!\n");
	fprintf(accountfile, "%s\n", username);
	fprintf(accountfile, "%s\n", password);
	fclose(accountfile);
}


void store_secret(pam_handle_t *pamh, pph_context *context){
	FILE* secretfile;
	int error = mount_ram(PPH_RAMDISK);
	if(error){
		pam_syslog(pamh, LOG_ERR, "PPH: Error saving account information%d \n", error);
		return;
	}		
	//make/open file in the mounted folder
	char pph_secret_file[MAX_PATH_LENGTH];
	if (strlen(PPH_RAMDISK) >(MAX_PATH_LENGTH - 10)){
		pam_syslog(pamh, LOG_ERR, "PPH: Path of the ramdisk is too long%d \n", error);
		return;
	}
	strcpy(pph_secret_file, PPH_RAMDISK);
	strcat(pph_secret_file, "secret");
	secretfile = fopen(pph_secret_file, "w+");
 
        if (secretfile == NULL){
          printf("can't save secret!" );
        }else {
          fwrite(context->secret, DIGEST_LENGTH, 1, secretfile);
	}
	fclose(secretfile);
}
void store_share_context(pam_handle_t *pamh, pph_context *context){
	FILE* sharefile;
	int error = mount_ram(PPH_RAMDISK);
	if(error){
		pam_syslog(pamh, LOG_ERR, "PPH: Error saving account information%d \n", error);
		return;
	}		
	//make/open file in the mounted folder
	char pph_share_file[MAX_PATH_LENGTH];
	if (strlen(PPH_RAMDISK) > (MAX_PATH_LENGTH - 10)){
		pam_syslog(pamh, LOG_ERR, "PPH: Path of the ramdisk is too long%d \n", error);
		return;
	}
	strcpy(pph_share_file, PPH_RAMDISK);
	strcat(pph_share_file, "account");
	sharefile = fopen(pph_share_file, "w+");

        if (sharefile == NULL){
          	printf("can't save secret!" );
        }else {
		fwrite(context->share_context, sizeof(gfshare_ctx), 1, sharefile);
		fwrite(context->share_context->sharenrs, context->share_context->sharecount, 1, sharefile);
		fwrite(context->share_context->buffer, context->share_context->buffersize, 1, sharefile);
	}
	fclose(sharefile);

}

void unlock_context(pam_handle_t *pamh, pph_context *context){
	FILE *accountfile;
	accountfile = fopen(PPH_ACCOUNT_FILE, "r");
	if (accountfile != NULL) {
		char pro_username[MAX_USERNAME_LENGTH];
		char pro_password[MAX_PASSWORD_LENGTH];
		int index = 0;
		int size = context->threshold;
		const uint8 **usernames = malloc(sizeof(*usernames)*size);
  		const uint8  **passwords = malloc(sizeof(*passwords)*size);
  		unsigned int *username_lengths = malloc(sizeof(*username_lengths)*size);
		unsigned int *password_lengths = malloc(sizeof(*password_lengths)*size);
		int unlockret;	
		while (fscanf(accountfile, "%s\n%s\n", pro_username, pro_password)!= EOF){
  			usernames[index] = strdup(pro_username); 
 			passwords[index] = strdup(pro_password);
			username_lengths[index] = strlen(pro_username);
			password_lengths[index] = strlen(pro_password);
			index++;
		}
		unlockret = pph_unlock_password_data(context, index+1, usernames, username_lengths, passwords, password_lengths);
		if (unlockret == PPH_ERROR_OK) {
			store_secret(pamh,context);
			store_share_context(pamh,context);
			fclose(accountfile);
			remove(accountfile);
		} else {
			fclose(accountfile);
		}
	}
}

int mount_ram(const char* theFile){
	struct stat data;
	struct stat parent_data;
	int error;
	int mount_error;
 	char parent[MAX_PATH_LENGTH]; 

	error = stat(theFile, &data);
	if (error) 
		return error;

	snprintf(parent, MAX_PATH_LENGTH, "%s/..", theFile);	
	error = stat(parent, &parent_data);
	if (error)
		return error;

	if ((data.st_dev != parent_data.st_dev) ||
		(data.st_dev == parent_data.st_dev && data.st_ino == parent_data.st_ino)) {
		return 0;
    	} else {
		mount_error= mount(theFile, theFile, "tmpfs", 0, "size=20m");
        	if(mount_error == 0){
			return mount_error;
		}
		return 1;
   	}
}

int load_accounts_shadow(pph_context *context){
	char buffer[4096];
	char name[MAX_USERNAME_LENGTH];
	char password[525];
	char others[125];
	const char s[2] = "$";
	char *token;
	//open shadow file to read and check the availability
	FILE *shadow;
	shadow = fopen("/etc/shadow", "r");
	if (shadow == NULL){
		return PPH_FILE_ERR;
	}

	context->account_data = NULL;
	while(fgets(buffer, sizeof buffer, shadow) != NULL){
		sscanf(buffer, "%128[^:]:%525[^:]:%s\n", name, password, others);
		token = strtok(password, s);
		if (strcmp(token, "PPH") == 0){
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
