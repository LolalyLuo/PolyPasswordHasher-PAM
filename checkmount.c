#include<sys/types.h>
#include<sys/stat.h>
#include<unistd.h>
#include<stdio.h>
#include<strings.h>
#include"config.h"

int mount_ram(const char* theFile);
int main(){
	int theErr;
	theErr = mount_ram("/home/lolaly/PolyPasswordHasher-PAM/ramdisk/");
	printf("the error is %d\n", theErr);
    
}

int mount_ram(const char* theFile){
	struct stat data;
	struct stat parent_data;
	int error;
 	char parent[200]; // should correct to the maximum pathlength

	printf("stating %s...\n", theFile);

	error = stat(theFile, &data);

	printf("[%d] stat'd finished\n", error);
	if (error) 
		return error;

	snprintf(parent, 200, "%s/..", theFile);	
	printf("stating %s...\n", parent);
	error = stat(parent, &parent_data);

	if (error)
		return error;

	printf("[%d] stat'd finished\n", error);

	if ((data.st_dev != parent_data.st_dev) ||
		(data.st_dev == parent_data.st_dev && data.st_ino == parent_data.st_ino)) {
		printf("is mountpoint\n");
    	} else {
        	printf("Is not mountpoint\n");
   	}

	return error;
}


