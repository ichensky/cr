#include <gcrypt.h>
#define AES256_KEY_SIZE     32
#define AES256_BLOCK_SIZE   16
#define HMAC_KEY_SIZE       64
#define KDF_ITERATIONS      50000
#define KDF_SALT_SIZE       128
#define KDF_KEY_SIZE        AES256_KEY_SIZE + HMAC_KEY_SIZE

int _cr_aes_init_cipher (gcry_cipher_hd_t *handle,
		 unsigned char *key,
		 unsigned char *init_vector);

void _cr_aes_cleanup (gcry_cipher_hd_t cipher,
	      gcry_mac_hd_t mac,
	      unsigned char *str,
	      unsigned char *str2,
	      unsigned char *str3);

int cr_aes_encrypt(const unsigned char *text,
	    const size_t text_len,
	    const void *password,
	    const size_t password_len,
	    unsigned char **packed_data,
	    size_t *packed_data_len);

int cr_aes_decrypt (const unsigned char *packed_data,
	     const int packed_data_len,
	     const void *password,
	     const size_t password_len,
	     unsigned char **ciphertext,
	     size_t *ciphertext_len,
	     size_t *pkcs7_padding);
