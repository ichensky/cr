#include<stddef.h>

size_t cr_file_read_file_into_buf (const char *filepath,
			   const long max_file_size,
			   unsigned char **data,
			   size_t *data_length
	);
size_t cr_file_write_buf_to_file (const char *filepath,
			  const unsigned char *data,
			  const size_t data_length);
