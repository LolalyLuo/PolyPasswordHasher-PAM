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
	openlog("PAM_PPH: ",LOG_NOWAIT, LOG_LOCAL1);
	pam_syslog(pamh, LOG_INFO, "PPH: pam_sm_authenticate is being called. \n");
	struct pam_conv *conv;
	struct pam_message msg;
	const struct pam_message *msgp;
	struct pam_response *resp;

	int retval, pam_err;
	const char* username;
	const char* password;
	
	//checking username and setup syslog
	retval = pam_get_user(pamh, &username, "Username(pam): ");	
	if (retval != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR, "PPH: can't access username. \n");
		return retval;
	}
	
	//get password 
	pam_err = pam_get_authtok(pamh, PAM_AUTHTOK, &password, "What is your password: ");
	if (pam_err != PAM_SUCCESS){

		pam_syslog(pamh, LOG_ERR, "PPH: can't get password. \n");
		return pam_err;
	}
	
	//verify password
	pam_syslog(pamh, LOG_INFO, "PPH: authenticating, got username &password. \n");

	
	return PAM_SUCCESS;
}	



//change password
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv){
	int retval;
	const char *user;
	const char *password;
	//authenticate user
	retval = pam_get_user(pamh, &user, NULL);
	if (retval != PAM_SUCCESS){
		pam_syslog(pamh, LOG_ERR, "PPH: Trouble getting username \n");
		return retval;
	}
	printf("================\n");
	
	retval = pam_get_authtok(pamh, PAM_AUTHTOK, &password, "NEW password: ");
	if (retval != PAM_SUCCESS){
		pam_syslog(pamh, LOG_ERR, "PPH: Can't get password \n");
		return retval;
	}
	pph_context *context;
	context =  pph_reload_context("/etc/PPHdata");
	if (context == NULL){
		pam_syslog(pamh, LOG_ERR, "PPH: Can't open context\n");
		return PAM_TRY_AGAIN;
	}
	retval = pph_create_account(context, user, strlen(user), password, strlen(password), 0);
	if (retval == PPH_ERROR_OK){
		pph_store_context(context, "/etc/PPHdata");
		pph_destroy_context(context);
		pam_syslog(pamh, LOG_INFO, "PPH: create a new user successfully\n");
		return PAM_SUCCESS;
	}
	else if (retval == PPH_ACCOUNT_EXISTS) {
		pph_change_password(context, user, strlen(user), password, strlen(password));
		
	}
	else {
		pam_syslog(pamh, LOG_ERR, "PPH: Can't change password currently %d \n", retval);	
		return PAM_TRY_AGAIN;
	}
}





