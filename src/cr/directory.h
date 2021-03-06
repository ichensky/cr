#include<stdlib.h>

typedef void cr_directory_handlefile(const char* filename);

size_t cr_directory_fileext(const char** exts,const size_t exts_len, const char* ext);

void cr_directory_files(const char *dirname,
			   const char** exts,
			   const size_t exts_len,
			   cr_directory_handlefile handlefile_ptr);
