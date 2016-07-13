#include <security/pam_appl.h>
#define _GNU_SOURCE
#include <security/pam_misc.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>

#define MAX_LENGTH_USERNAME  50
const struct pam_conv conv = {
	misc_conv,
	NULL
};

int main(int argc, char *argv[]) {
	pam_handle_t* pamh = NULL;
	int retval;
	char *user;
	user = malloc(MAX_LENGTH_USERNAME);
	struct passwd *user_info;
	
/*	user_info = getpwuid(getuid());
	if (!user_info)  {
		int errsv = errno;
		printf("couldn't get user %s!\n", strerror(errsv));
		return -1;
	}


	if (setresuid(0, 0, 0)) {
		int errsv = errno;
		printf("Couldn't set ourselves to root %s\n", strerror(errsv));
		return -1;
	}*/
	printf("Username(app): ");
	scanf("%s", user);
	
/*	printf("user is %s, user_info->pw_name is %s \n", user, user_info->pw_name);

	if (strcmp(user_info->pw_name, user) && strcmp("root", user_info->pw_name)) {
		printf("You can't change info for %s\n", user);
		return -1;
	}
*/
	printf("2=================================================\n");
	//printf("the user is: %s\n", user_info->pw_name);
	retval = pam_start("PAM_PPH", user, &conv, &pamh);
	printf("3=================================================\n");
	// Are the credentials correct?
	if (retval == PAM_SUCCESS) {
		printf("Credentials accepted.\n");
		retval = pam_acct_mgmt(pamh, 0);
	}
	printf("5=================================================\n");
	// Can the accound be used at this time?
	if (retval == PAM_SUCCESS) {
		printf("Account is valid.\n");
		retval = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK);
		printf("app:!!!!!the err is: %d\n", retval);
	}
	printf("6=================================================\n");
	printf("app:!!!!!the err is: %d\n", retval);
	if (retval == PAM_SUCCESS) {
		printf("Authenticated\n");
	} else if (retval == PAM_CRED_INSUFFICIENT) {
		printf("It is not a PPH account\n");
	} else if (retval == PAM_USER_UNKNOWN) {
		printf("The user does not exist\n");
	} else {
		printf("%s\n", pam_strerror(pamh, retval));
	}	
	

	printf("7=================================================\n");
/*	//change password
	if (retval == PAM_SUCCESS) {
		printf("Now you have to change your password\n");
		do {
            		retval = pam_chauthtok(pamh, PAM_SILENT);
			printf("error message: %s\n", pam_strerror(pamh, retval));
        	} while (retval == PAM_AUTHTOK_ERR);
		
	}*/
	
	// close PAM (end session)
	if (pam_end(pamh, retval) != PAM_SUCCESS) {
		pamh = NULL;
		printf("check_user: ailed to release authenticator\n");
		exit(1);
	}
	printf("8=================================================\n");
	return retval == PAM_SUCCESS ? 0 : 1;
}
