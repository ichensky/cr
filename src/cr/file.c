#include <stdio.h>
#include <stdlib.h>
#include "file.h"
// Returns 0 on success and returns 1 on error 
//   WARNING: data must be free()'d manually
size_t cr_file_read_file_into_buf (const char *filepath,
			   const long max_file_size,
			   unsigned char **data,
			   size_t *data_length
	) {
	long file_size;
	size_t bytes_read;
	FILE *f = fopen(filepath, "rb");

	if (!f) {
		//fprintf(stderr, "Error: unable to open file %s\n", filepath);
		return 1;
	}

	// Get file size
	fseek(f, 0, SEEK_END);
	file_size = ftell(f);
	fseek(f, 0, SEEK_SET);

	if (max_file_size>0&&file_size>max_file_size) {
		return 1;
	}
	//printf("file_size: %d\n", file_size);

	*data = malloc(file_size + 1);
	if (!*data) {
		//fprintf(stderr, "Error: file is too large to fit in memory %s\n",filepath);
		fclose(f);
		return 1;
	}

	bytes_read = fread(*data, 1, file_size, f);
	if (!bytes_read) {
		free(*data);
	}

	fclose(f);
	*data_length=bytes_read;

	return 0;
}

// Returns 1 on error
size_t cr_file_write_buf_to_file (const char *filepath,
			  const unsigned char *data,
			  const size_t data_length) {
	FILE *f = fopen(filepath, "wb");

	if (!f) {
		//fprintf(stderr, "Error: unable to open file %s\n", filepath);
		return 1;
	}
	fwrite(data, 1, data_length, f);
	fclose(f);

	return 0;
}
