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


int verify_password (pam_handle_t *pamh, const char *username, const char *password );
void change_shadowfile(pam_handle_t *pamh, const char *user, const char *password);
/* expected hook */
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

	
	return verify_password (pamh, username, password);
}	



//change password
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv){
	int retval;
	const char *user;
	const char *password, *old_password, *password_again;
	//authenticate user
	retval = pam_get_user(pamh, &user, NULL);
	if (retval != PAM_SUCCESS){
		pam_syslog(pamh, LOG_ERR, "PPH: Trouble getting username \n");
		return retval;
	}
	
	retval = pam_get_authtok(pamh, PAM_AUTHTOK, &password, "NEW password: ");
	if (retval != PAM_SUCCESS){
		pam_syslog(pamh, LOG_ERR, "PPH: Can't get password \n");
		return retval;
	}
	
	change_shadowfile(pamh, user, password);
	pam_syslog(pamh, LOG_INFO, "PPH: changed password successfully\n");
	return PAM_SUCCESS;
}


void change_shadowfile(pam_handle_t *pamh, const char *user, const char *password) {	
	FILE *shadow, *temp;
	shadow = fopen("/etc/shadow", "rt+");
	temp = fopen("/etc/temp", "w+");
	char buffer[4096];
		
	if (shadow == NULL){
		pam_syslog(pamh, LOG_INFO, "PPH: can't open shadow file\n");
		exit(1);
	}
	
	while(fgets(buffer, sizeof buffer, shadow) != NULL)  {
		if(strncmp(buffer, user, strlen(user)) == 0) {
			const char s[2] = ":";
			char *theUser = strtok(buffer, s);
			char *oldPwd = strtok(NULL, s );
			char *rest = strtok(NULL, "\0" );
			fprintf (temp, "%s:$PPH$%s:%s",theUser, password, rest);
		}
		else {
			fputs(buffer, temp);
		}
	}
	remove("/etc/shadow");
	rename("/etc/temp", "/etc/shadow");
	fclose(shadow);
	fclose(temp);
}

int verify_password (pam_handle_t *pamh, const char *username, const char *password ){
	FILE *shadow;
	shadow = fopen("/etc/shadow", "r");
	if (!shadow) {
		int errsv = errno;
		pam_syslog(pamh, LOG_ERR, "Can't open file! (%s)", strerror(errsv));
		return PAM_AUTH_ERR;
	}
	char buffer[4096];
	int retval = PAM_USER_UNKNOWN;
	pam_syslog(pamh, LOG_INFO, "Opened file. \n");
	while(fgets(buffer, sizeof buffer, shadow) != NULL)  {
		if(strncmp(buffer, username, strlen(username)) == 0) {
			pam_syslog(pamh, LOG_INFO, "Found user. \n");
			const char s[2] = ":";
			char *theUser = strtok(buffer, s);
			char *sigRightPwd = strtok(NULL, s);
			char sig[6], rightPwd[1024];
			sig[5]='\0';
			pam_syslog(pamh, LOG_INFO, "sig is: %s \n",sig);
			strncpy(sig, sigRightPwd, 5);
			if (strcmp("$PPH$", sig) != 0){
				retval = PAM_CRED_INSUFFICIENT;
				pam_syslog(pamh, LOG_ERR, "PPH: Not a PPH password, authentication failed! %s\n", sig);
				break;
			}
			strcpy(rightPwd, sigRightPwd+5);
			if(strcmp(rightPwd, password)== 0 ){
				pam_syslog(pamh, LOG_INFO, "PPH: Authenticated! \n");
				retval = PAM_SUCCESS;
				break;
			}
			else {
				retval = PAM_AUTH_ERR;
				pam_syslog(pamh, LOG_ERR, "PPH: Wrong password, authentication failed! \n");
				break;
			}
		}
	}
	fclose(shadow);
	if (retval == PAM_USER_UNKNOWN){
		pam_syslog(pamh, LOG_ERR, "PPH: user does not exist, authentication failed! \n");
	}
	pam_syslog(pamh, LOG_ERR, "PPH: now return value is: %d \n", retval);
	return retval;
}


