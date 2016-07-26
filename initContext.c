#include <libpolypasswordhasher.h>


int main() {
        PPH_ERROR error;
	pph_context *context;
  	printf("initial context\n");
  	uint8 threshold;
  	printf("Enter the number of threshold (from 1 to MAX_ACCOUNTS),recommand 2\n");
  	scanf("%d",&threshold);   
                          
  	uint8 isolated_check_bits;
  	printf("Enter the number of threshold (from 1 to MAX_ACCOUNTS),recommand 2\n");
  	scanf("%d",&isolated_check_bits);

	context = pph_init_context(threshold, isolated_check_bits);

	error = pph_store_context(context, "/home/lolaly/PolyPasswordHasher-PAM/PPHdata");
        if (error != PPH_ERROR_OK){
          printf("can't store context, erorr: %d \n", error);
	}
        FILE* secretfile;
        secretfile = fopen("/home/lolaly/PolyPasswordHasher-PAM/ramdisk/secret", "w+");
        if (secretfile == NULL){
          printf("can't save secret!" );
        }else {
          fprintf(secretfile, "%s", context->secret);
	}
	fclose(secretfile);
	pph_destroy_context(context);
	printf("context is initialed and stored!\n");
} 
