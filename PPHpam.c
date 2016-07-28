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
#define MAX_PASSWD_TRIES 3

void get_secret(pph_context *context);

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
	struct pam_conv *conv;
	struct pam_message msg;
	const struct pam_message *msgp;
	struct pam_response *resp;

	int retval;
	int error = -1;
	const char* username;
	const char* password;
	int retry = 0;
	pph_context *context;
	
	
	//return PAM_SUCCESS;
	//set up syslog
	openlog("PAM_PPH: ",LOG_NOWAIT, LOG_LOCAL1);
	pam_syslog(pamh, LOG_INFO, "PPH: pam_sm_authenticate is being called. \n");
	
	//load context and secret if available
	context =  pph_reload_context("/home/lolaly/PolyPasswordHasher-PAM/PPHdata");
	if (context == NULL){
		pam_syslog(pamh, LOG_ERR, "PPH: Can't open context\n");
		return PAM_AUTHINFO_UNAVAIL;
	}
	pam_syslog(pamh, LOG_INFO, "PPH: context is loaded. \n");
	get_secret(context);
	//if the secret is available, inform the system		
	if (context->secret != NULL) {
		pam_syslog(pamh, LOG_ERR,"secret is now available, it is %s\n", context->secret);
	} else {
		//if the secret is not available, check if there is enough shares to unlock the secret
	}
	pam_syslog(pamh, LOG_INFO, "PPH: secret is loaded  \n");
	//authenticate the user with PPH
	

	//get username from user
	pam_syslog(pamh, LOG_ERR, "PPH: in the loop. \n");
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


	//after authentication, destroy the context we used
	if (pph_destroy_context(context) != PPH_ERROR_OK){
		pam_syslog(pamh, LOG_ERR, "PPH: Can't destroy context\n");
		return PAM_AUTH_ERR;
	}
	pam_syslog(pamh, LOG_ERR, "PPH: before return ,the error is %d \n", error);
	
//	username = password = NULL;
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
	openlog("PAM_PPH: ",LOG_NOWAIT, LOG_LOCAL1);
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
	get_secret(context);
	//if the secret is available, inform the system		
	if (context->secret != NULL) {
		pam_syslog(pamh, LOG_ERR,"secret is now available, it is %s\n", context->secret);
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
		exit(1);
	}
	
	if (pph_destroy_context(context) != PPH_ERROR_OK){
		pam_syslog(pamh, LOG_ERR, "PPH: Can't destroy context %d \n", error);
		exit(1);
	}
	closelog();
	//lastly, return the right PAM value
	if (error == PPH_ERROR_OK) {
		return PAM_SUCCESS;
	} else {
		return 	PAM_AUTHTOK_LOCK_BUSY;
	}
	
}


void get_secret(pph_context *context){
	FILE *secretfile;
	//uint8 *thesecret;
	secretfile = fopen("/home/lolaly/PolyPasswordHasher-PAM/ramdisk/secret", "r");
	if (secretfile == NULL) {
 		return;
	}
	char buffer[1024];
	//thesecret = malloc(sizeof buffer);
	//thesecret = fgets(buffer, sizeof buffer, secretfile);
	context->secret =malloc(fgets(buffer, sizeof buffer, secretfile));
	fclose(secretfile);
}


