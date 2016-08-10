#include <libpolypasswordhasher.h>
#include "libgfshare.h"
#include "config.h"

struct _gfshare_ctx {
  unsigned int sharecount;
  unsigned int threshold;
  unsigned int size;
  unsigned char* sharenrs;
  unsigned char* buffer;
  unsigned int buffersize;
};

void store_secret(pph_context *context);
void store_share_context(pph_context *context);
int main() {
        PPH_ERROR error;
	pph_context *context;
  	printf("initial context\n");

	context = pph_init_context(THRESHOLD, ISOLATED_CHECK_BITS);

	//make some account to test with!  
	error = pph_create_account(context, "abc", strlen("abc"),
                       "123",strlen("123"), 0);
  
	error = pph_create_account(context, "abcabc", strlen("abcabc"),
                       "345",strlen("345"), 2);

	error = pph_create_account(context, "theabc", strlen("theabc"),
                       "567",strlen("567"), 1);
	
	//test code ended 
	error = pph_store_context(context, CONTEXT_FILE);
        if (error != PPH_ERROR_OK){
          printf("can't store context, erorr: %d \n", error);
	}
        
	store_secret(context);
	store_share_context(context);

	pph_destroy_context(context);

	//make a bootstrap account 
	context =  pph_reload_context(CONTEXT_FILE);
	context->is_normal_operation = false;
	pph_create_account(context, "what", strlen("what"),
                       "123",strlen("123"), 0);
	pph_store_context(context, CONTEXT_FILE);

	pph_destroy_context(context);
	printf("context is initialed and stored!\n");
} 


void store_secret(pph_context *context){
	FILE* secretfile;
        secretfile = fopen(SECRET_FILE, "w+");
        if (secretfile == NULL){
          printf("can't save secret!" );
        }else {
          fwrite(context->secret, DIGEST_LENGTH, 1, secretfile);
	}
	fclose(secretfile);
}
void store_share_context(pph_context *context){
	FILE* sharefile;
	sharefile = fopen(SHARE_FILE, "w+");
        if (sharefile == NULL){
          	printf("can't save share context!" );
        }else {
		fwrite(context->share_context, sizeof(gfshare_ctx), 1, sharefile);
		fwrite(context->share_context->sharenrs, context->share_context->sharecount, 1, sharefile);
		fwrite(context->share_context->buffer, context->share_context->buffersize, 1, sharefile);
	}
	fclose(sharefile);

}

