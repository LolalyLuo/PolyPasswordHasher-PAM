#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define PAM_SM_PASSWORD
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#include <syslog.h>
#include <errno.h>
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
void store_secret(pph_context *context);
void store_share_context(pph_context *context);

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
	/*struct pam_conv *conv;
	struct pam_message msg;
	const struct pam_message *msgp;
	struct pam_response *resp;*/

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
	//set up syslog
	pam_syslog(pamh, LOG_INFO, "PPH: pam_sm_authenticate is being called. \n");
	
	//load context and secret if available
	context =  pph_reload_context("/home/lolaly/PolyPasswordHasher-PAM/PPHdata");
	if (context == NULL){
		pam_syslog(pamh, LOG_ERR, "PPH: Can't open context\n");
		return PAM_AUTHINFO_UNAVAIL;
	}
	pam_syslog(pamh, LOG_INFO, "PPH: context is loaded. \n");
	

	context->is_normal_operation = false;
	//load secret and share context if available. 
	get_secret(context);
	get_share_context(context);
	//if the secret and share are still not available, try to unlock them		
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

	pam_syslog(pamh, LOG_ERR, "PPH: username: %s, password: %s\n", username, password);
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
	

	//If the account authenticated is a protector account, put it into a file
	//for bootstrapping purpose
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
			store_account(username, password);
			unlock_context(context);
			}
		}
	}

	
	//after authentication, destroy the context we used
	if (pph_destroy_context(context) != PPH_ERROR_OK){
		pam_syslog(pamh, LOG_ERR, "PPH: Can't destroy context\n");
	}
	
	//if autheticated successfully and the secret is not available, 
	//check if the account is a protector account and save shares
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

	//set up syslog
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
	context =  pph_reload_context("/home/lolaly/PolyPasswordHasher-PAM/PPHdata");
	if (context == NULL){
		pam_syslog(pamh, LOG_ERR, "PPH: Can't open context\n");
		return PAM_AUTHTOK_LOCK_BUSY;
	}
	
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
	pam_syslog(pamh, LOG_ERR, "PPH: the return value of pph_create_account is %d\n", error);
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
	//up to here we can store/destroy context
	if (pph_store_context(context, "/home/lolaly/PolyPasswordHasher-PAM/PPHdata") != PPH_ERROR_OK){
		pam_syslog(pamh, LOG_ERR, "PPH: Can't store context %d \n", error);
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
	secretfile = fopen("/home/lolaly/PolyPasswordHasher-PAM/ramdisk/secret", "r");
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
	sharefile = fopen("/home/lolaly/PolyPasswordHasher-PAM/ramdisk/share", "r");
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

void store_account(const char* username, const char* password){
	FILE *accountfile;
	accountfile = fopen("/home/lolaly/PolyPasswordHasher-PAM/ramdisk/account", "a");
	if (accountfile == NULL) {
 		return;
	}
	printf("saving account data!\n");
	fprintf(accountfile, "%s\n", username);
	fprintf(accountfile, "%s\n", password);
	fclose(accountfile);
}


void store_secret(pph_context *context){
	FILE* secretfile;
        secretfile = fopen("/home/lolaly/PolyPasswordHasher-PAM/ramdisk/secret", "w+");
        if (secretfile == NULL){
          printf("can't save secret!" );
        }else {
          fwrite(context->secret, DIGEST_LENGTH, 1, secretfile);
	}
	fclose(secretfile);
}
void store_share_context(pph_context *context){
	FILE* sharefile;
	sharefile = fopen("/home/lolaly/PolyPasswordHasher-PAM/ramdisk/share", "w+");
        if (sharefile == NULL){
          	printf("can't save secret!" );
        }else {
		fwrite(context->share_context, sizeof(gfshare_ctx), 1, sharefile);
		fwrite(context->share_context->sharenrs, context->share_context->sharecount, 1, sharefile);
		fwrite(context->share_context->buffer, context->share_context->buffersize, 1, sharefile);
	}
	fclose(sharefile);

}

void unlock_context(pph_context *context){
	FILE *accountfile;
	accountfile = fopen("/home/lolaly/PolyPasswordHasher-PAM/ramdisk/account", "r");
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
			store_secret(context);
			store_share_context(context);
			fclose(accountfile);
			remove(accountfile);
		} else {
			fclose(accountfile);
		}
	}
}



