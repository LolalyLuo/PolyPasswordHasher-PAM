/*this configuration file defines data need to initialize PPH 
and full path of files needed to use PAM*/

//the isolated check bits needed
#define ISOLATED_CHECK_BITS 2

//the max length of path
#define MAX_PATH_LENGTH 200
//path to save/restore context
#define PPH_CONTEXT_FILE "/home/lolaly/PolyPasswordHasher-PAM/PPHdata"

//everything below this line has to be files exist in ram memory
//path to a file where secret, share context and account data will be saved at
#define PPH_RAMDISK "/home/lolaly/PolyPasswordHasher-PAM/ramdisk/"

//path to save/get secret
#define PPH_SECRET_FILE "/home/lolaly/PolyPasswordHasher-PAM/ramdisk/secret"

//path to save/get share context
#define PPH_SHARE_FILE "/home/lolaly/PolyPasswordHasher-PAM/ramdisk/share"

//path to save/get protector account data
#define PPH_ACCOUNT_FILE "/home/lolaly/PolyPasswordHasher-PAM/ramdisk/account"
