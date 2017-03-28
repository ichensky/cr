#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include "directory.h"

#ifdef HAVE_DIRENT_D_TYPE_DT_DIR
# define cr_directory_is_dir(ent) ((ent->d_type)==DT_DIR)

#else
# include <sys/types.h>
# include <sys/stat.h>
# include <unistd.h>

static __inline__
int cr_directory_is_dir(const char *path){
	struct stat info;
	if(!stat(path,&info)){
		return S_ISDIR(info.st_mode);
	}
	return 0;
}

#endif


void cr_directory_files(const char *dirname,
			const char** exts,
			const size_t exts_len,
			cr_directory_handlefile handlefile_ptr){
	DIR * dir;
	struct dirent *de;

	dir=opendir(dirname);
	if(!dir){
		return;
	}

	while((de=readdir(dir))){
		if(!strcmp(de->d_name,".")||!strcmp(de->d_name,"..")){
			continue;
		}
		char *path=malloc(strlen(dirname)+strlen(de->d_name)+2);
		sprintf(path,"%s/%s",dirname,de->d_name);
		if(cr_directory_is_dir(path)){
			cr_directory_files(path,exts,exts_len,handlefile_ptr);
		}else{
			char *s=strrchr(de->d_name,'.');
			if(s!=NULL
			   &&!cr_directory_fileext(exts,exts_len,s)) {
				sprintf(path,"%s/%s",dirname,de->d_name);
				handlefile_ptr(path);
			}

		}
		free(path);

	}
	closedir(dir);
}

size_t cr_directory_fileext(const char** exts,const size_t exts_len,const char* ext){
	if (exts==NULL||exts_len==0) {
		return 0;
	}
	
	size_t i;
	for (i = 0; i < exts_len; i++) {
		if (!strcasecmp(exts[i], ext)) {
			return 0;
		
		}	
	}

	return 1;
}
