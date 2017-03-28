#include <stdlib.h>


typedef struct {
	size_t max_file_enc_size; // 40*1024*1024 //40mb
	void *password;
	size_t password_len;
	const char **dirnames;
	size_t dirnames_len;
	const char **exts;
	size_t exts_len;
} cr_crypt_config_type;
cr_crypt_config_type *cr_crypt_config;

size_t cr_crypt_encrypt_file_with_pass (const char *infile,
					const char *outfile);
size_t cr_crypt_decrypt_file_with_pass (const char *infile,
			   const char *outfile);

void cr_crypt_init(cr_crypt_config_type *config);
void cr_crypt_encrypt_file(const char *filename);
void cr_crypt_decrypt_file(const char *filename);
void cr_crypt_encrypt();
void cr_crypt_dencrypt();
void cr_crypt_print();
void cr_crypt_print_file(const char* filename);



