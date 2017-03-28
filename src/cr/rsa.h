#include<gcrypt.h>


size_t cr_rsa_key_gen(unsigned char **public_key,
		      size_t *public_key_len,
		      unsigned char **private_key,
		      size_t *private_key_len);

void cr_rsa_cert_file_names(const char *fname,
			    const size_t fname_len,
			    char **fnamep,
			    char **fnames);

size_t cr_rsa_encrypt(const unsigned char *public_key,
		      const size_t public_key_len,
		      const unsigned char *text,
		      const size_t text_len,
		      unsigned char **packed_data,
		      size_t *packed_data_len
	);

size_t cr_rsa_decrypt(const unsigned char *private_key,
		      const size_t private_key_len,
		      const unsigned char *packed_data,
		      const size_t packed_data_len,
		      unsigned char **text,
		      size_t *text_len);

size_t cr_rsa_sign(const unsigned char *private_key,
		   const size_t private_key_len,
		   const unsigned char *data,
		   const size_t data_len,
		   unsigned char **sign_data,
		   size_t *sign_data_len);

size_t cr_rsa_verify(const unsigned char *public_key,
		     const size_t public_key_len,
		     const unsigned char *data,
		     const size_t data_len,
		     const unsigned char *sign_data,
		     const size_t sign_data_len);
