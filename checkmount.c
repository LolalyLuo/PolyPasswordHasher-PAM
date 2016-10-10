#include<sys/types.h>
#include<sys/stat.h>
#include<unistd.h>
#include<stdio.h>
#include<string.h>
#include <errno.h> 
#include <sys/mount.h>
#include"config.h"

int mount_ram(const char* theFile);
int main(){
	int theErr;
	theErr = mount_ram("/home/lolaly/PolyPasswordHasher-PAM/ramdisk/");
	printf("the error number is %d\n", theErr);
    
}

int mount_ram(const char* theFile){
	struct stat data;
	struct stat parent_data;
	int error;
	int mount_error;
 	char parent[200]; // should correct to the maximum pathlength

	error = stat(theFile, &data);
	if (error) 
		return error;

	snprintf(parent, 200, "%s/..", theFile);	
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


