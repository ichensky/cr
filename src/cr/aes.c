#include "aes.h"

int _cr_aes_init_cipher (gcry_cipher_hd_t *handle, unsigned char *key, unsigned char *init_vector) {
	gcry_error_t err;

	// 256-bit AES using cipher-block chaining;
	// with ciphertext stealing, no manual padding is required
	err = gcry_cipher_open(handle,
			       GCRY_CIPHER_AES256,
			       GCRY_CIPHER_MODE_CBC,
			       GCRY_CIPHER_CBC_CTS
		);
	if (err) {
		//fprintf(stderr, "cipher_open: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
		return 1;
	}

	err = gcry_cipher_setkey(*handle, key, AES256_KEY_SIZE);
	if (err) {
		//fprintf(stderr, "cipher_setkey: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
		gcry_cipher_close(*handle);
		return 1;
	}

	err = gcry_cipher_setiv(*handle, init_vector, AES256_BLOCK_SIZE);
	if (err) {
		//fprintf(stderr, "cipher_setiv: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
		gcry_cipher_close(*handle);
		return 1;
	}

	return 0;
}

void _cr_aes_cleanup (gcry_cipher_hd_t cipher, gcry_mac_hd_t mac,
	      unsigned char *str, unsigned char *str2, unsigned char *str3) {
	if (cipher != NULL) gcry_cipher_close(cipher);
	if (mac != NULL)    gcry_mac_close(mac);

	if (str != NULL)  free(str);
	if (str2 != NULL) free(str2);
	if (str3 != NULL) free(str3);
}

	
int cr_aes_encrypt(const unsigned char *text,
	    const size_t text_len,
	    const void *password,
	    const size_t password_len,
	    unsigned char **packed_data,
	    size_t *packed_data_len){
unsigned char init_vector[AES256_BLOCK_SIZE],
		kdf_salt[KDF_SALT_SIZE],
		kdf_key[KDF_KEY_SIZE],
		aes_key[AES256_KEY_SIZE],
	hmac_key[HMAC_KEY_SIZE],
		*ciphertext,
	*hmac,
	*pkcs7_padding_text
		;
size_t blocks_required, hmac_len,
	pkcs7_padding,
i
	;
	gcry_cipher_hd_t handle;
	gcry_mac_hd_t mac;
	gcry_error_t err;

	// Find number of blocks required for data
	blocks_required = text_len / AES256_BLOCK_SIZE;
	pkcs7_padding=text_len%AES256_BLOCK_SIZE;
	if (pkcs7_padding != 0) {
		// Check pkcs7 padding
		pkcs7_padding=AES256_BLOCK_SIZE-pkcs7_padding;
		pkcs7_padding_text=malloc(pkcs7_padding);
		for(i=0;i<pkcs7_padding;i++){
			pkcs7_padding_text[i]=pkcs7_padding;
		}
		blocks_required++;
	}

	// Generate 128 byte salt in preparation for key derivation
	gcry_create_nonce(kdf_salt, KDF_SALT_SIZE);

	// Key derivation: PBKDF2 using SHA512 w/ 128 byte salt over 10 iterations into a 64 byte key
	err = gcry_kdf_derive(password,
			      password_len,
			      GCRY_KDF_PBKDF2,
			      GCRY_MD_SHA512,
			      kdf_salt,
			      KDF_SALT_SIZE,
			      KDF_ITERATIONS,
			      KDF_KEY_SIZE,
			      kdf_key);
	if (err) {
		//fprintf(stderr, "kdf_derive: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
		return 1;
	}

	// Copy the first 32 bytes of kdf_key into aes_key
	memcpy(aes_key, kdf_key, AES256_KEY_SIZE);

	// Copy the last 32 bytes of kdf_key into hmac_key
	memcpy(hmac_key, &(kdf_key[AES256_KEY_SIZE]), HMAC_KEY_SIZE);

	// Generate the initialization vector
	gcry_create_nonce(init_vector, AES256_BLOCK_SIZE);

	// Begin encryption
	if (_cr_aes_init_cipher(&handle, aes_key, init_vector)) {
		return 1;
	}

	// Make new buffer of size blocks_required * AES256_BLOCK_SIZE for in-place encryption
	ciphertext = malloc(blocks_required * AES256_BLOCK_SIZE+pkcs7_padding);
	if (ciphertext == NULL) {
		//fprintf(stderr, "Error: unable to allocate memory for the ciphertext\n");
		_cr_aes_cleanup(handle, NULL, NULL, NULL, NULL);
		return 1;
	}
	if(pkcs7_padding != 0){
		memcpy(ciphertext, pkcs7_padding_text, pkcs7_padding);
		_cr_aes_cleanup(NULL, NULL, pkcs7_padding_text, NULL, NULL);
	}
	memcpy(ciphertext+pkcs7_padding, text, blocks_required * AES256_BLOCK_SIZE);

	// Encryption is performed in-place
	err = gcry_cipher_encrypt(handle, ciphertext, AES256_BLOCK_SIZE * blocks_required, NULL, 0);
	if (err) {
		//fprintf(stderr, "cipher_encrypt: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
		_cr_aes_cleanup(handle, NULL, ciphertext, NULL, NULL);
		return 1;
	}

	// Compute and allocate space required for packed data
	hmac_len = gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA512);
	*packed_data_len = KDF_SALT_SIZE + AES256_BLOCK_SIZE + (AES256_BLOCK_SIZE * blocks_required) + hmac_len;
	*packed_data = malloc(*packed_data_len);
	if (*packed_data == NULL) {
		//fprintf(stderr, "Unable to allocate memory for packed data\n");
		_cr_aes_cleanup(handle, NULL, ciphertext, NULL, NULL);
		return 1;
	}

	// Pack data before writing: salt::IV::ciphertext::HMAC where "::" denotes concatenation
	memcpy(*packed_data, kdf_salt, KDF_SALT_SIZE);
	memcpy(&((*packed_data)[KDF_SALT_SIZE]), init_vector, AES256_BLOCK_SIZE);
	memcpy(&((*packed_data)[KDF_SALT_SIZE + AES256_BLOCK_SIZE]), ciphertext, AES256_BLOCK_SIZE * blocks_required);

	// Begin HMAC computation on encrypted/packed data
	hmac = malloc(hmac_len);
	if (hmac == NULL) {
		//fprintf(stderr, "Error: unable to allocate enough memory for the HMAC\n");
		_cr_aes_cleanup(handle, NULL, ciphertext, *packed_data, NULL);
		return 1;
	}

	err = gcry_mac_open(&mac, GCRY_MAC_HMAC_SHA512, 0, NULL);
	if (err) {
		//fprintf(stderr, "mac_open during encryption: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
		_cr_aes_cleanup(handle, NULL, ciphertext, *packed_data, hmac);
		return 1;
	}

	err = gcry_mac_setkey(mac, hmac_key, HMAC_KEY_SIZE);
	if (err) {
		//fprintf(stderr, "mac_setkey during encryption: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
		_cr_aes_cleanup(handle, mac, ciphertext, *packed_data, hmac);
		return 1;
	}

	// Add packed_data to the MAC computation
	err = gcry_mac_write(mac, *packed_data, *packed_data_len - hmac_len);
	if (err) {
		//fprintf(stderr, "mac_write during encryption: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
		_cr_aes_cleanup(handle, mac, ciphertext, *packed_data, hmac);
		return 1;
	}

	// Finalize MAC and save it in the hmac buffer
	err = gcry_mac_read(mac, hmac, &hmac_len);
	if (err) {
		//fprintf(stderr, "mac_read during encryption: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
		_cr_aes_cleanup(handle, mac, ciphertext, *packed_data, hmac);
		return 1;
	}

	// Append the computed HMAC to packed_data
	memcpy(&((*packed_data)[KDF_SALT_SIZE + AES256_BLOCK_SIZE
			     + (AES256_BLOCK_SIZE * blocks_required)]), hmac, hmac_len);

	_cr_aes_cleanup(handle, mac, ciphertext, NULL, hmac);

	return 0;
}

int cr_aes_decrypt (const unsigned char *packed_data,
	     const int packed_data_len,
	     const void *password,
	     const size_t password_len,
	     unsigned char **ciphertext,
	     size_t *ciphertext_len,
	     size_t *pkcs7_padding){

unsigned char init_vector[AES256_BLOCK_SIZE],
		kdf_salt[KDF_SALT_SIZE],
		kdf_key[KDF_KEY_SIZE],
		aes_key[AES256_KEY_SIZE],
		hmac_key[HMAC_KEY_SIZE],
		*hmac;
	  
size_t  hmac_len,
	i
	;
	gcry_cipher_hd_t handle;
	gcry_mac_hd_t mac;
	gcry_error_t err;

	// Compute necessary lengths
	hmac_len = gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA512);
	*ciphertext_len = packed_data_len - KDF_SALT_SIZE - AES256_BLOCK_SIZE - hmac_len;

	*ciphertext = malloc(*ciphertext_len);
	if (*ciphertext == NULL) {
		//fprintf(stderr, "Error: ciphertext is too large to fit in memory\n");
		return 1;
	}

	hmac = malloc(hmac_len);
	if (hmac == NULL) {
		//fprintf(stderr, "Error: could not allocate memory for HMAC\n");
		_cr_aes_cleanup(NULL, NULL, *ciphertext, NULL, NULL);
		return 1;
	}

	// Unpack data
	memcpy(kdf_salt, packed_data, KDF_SALT_SIZE);
	memcpy(init_vector, &(packed_data[KDF_SALT_SIZE]), AES256_BLOCK_SIZE);
	memcpy(*ciphertext, &(packed_data[KDF_SALT_SIZE + AES256_BLOCK_SIZE]), *ciphertext_len);
	memcpy(hmac, &(packed_data[KDF_SALT_SIZE + AES256_BLOCK_SIZE + *ciphertext_len]), hmac_len);

	// Key derivation: PBKDF2 using SHA512 w/ 128 byte salt over 10 iterations into a 64 byte key
	err = gcry_kdf_derive(password,
			      password_len,
			      GCRY_KDF_PBKDF2,
			      GCRY_MD_SHA512,
			      kdf_salt,
			      KDF_SALT_SIZE,
			      KDF_ITERATIONS,
			      KDF_KEY_SIZE,
			      kdf_key);
	if (err) {
		//fprintf(stderr, "kdf_derive: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
		_cr_aes_cleanup(NULL, NULL, *ciphertext, NULL, hmac);
		return 1;
	}

	// Copy the first 32 bytes of kdf_key into aes_key
	memcpy(aes_key, kdf_key, AES256_KEY_SIZE);

	// Copy the last 32 bytes of kdf_key into hmac_key
	memcpy(hmac_key, &(kdf_key[AES256_KEY_SIZE]), HMAC_KEY_SIZE);

	// Begin HMAC verification
	err = gcry_mac_open(&mac, GCRY_MAC_HMAC_SHA512, 0, NULL);
	if (err) {
		//fprintf(stderr, "mac_open during decryption: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
		_cr_aes_cleanup(handle, NULL, *ciphertext, NULL, hmac);
		return 1;
	}

	err = gcry_mac_setkey(mac, hmac_key, HMAC_KEY_SIZE);
	if (err) {
		//fprintf(stderr, "mac_setkey during decryption: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
		_cr_aes_cleanup(handle, mac, *ciphertext, NULL, hmac);
		return 1;
	}

	err = gcry_mac_write(mac, packed_data, KDF_SALT_SIZE + AES256_BLOCK_SIZE + *ciphertext_len);
	if (err) {
		//fprintf(stderr, "mac_write during decryption: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
		_cr_aes_cleanup(handle, mac, *ciphertext, NULL, hmac);
		return 1;
	}

	// Verify HMAC
	err = gcry_mac_verify(mac, hmac, hmac_len);
	if (err) {
		//fprintf(stderr, "HMAC verification failed: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
		_cr_aes_cleanup(handle, mac, *ciphertext, NULL, hmac);
		return 1;
	} else {
		//printf("Valid HMAC found\n");
	}

	// Begin decryption
	if (_cr_aes_init_cipher(&handle, aes_key, init_vector)) {
		_cr_aes_cleanup(handle, mac, *ciphertext, NULL, hmac);
		return 1;
	}

	err = gcry_cipher_decrypt(handle, *ciphertext, *ciphertext_len, NULL, 0);
	if (err) {
		//fprintf(stderr, "cipher_decrypt: %s/%s\n", gcry_strsource(err), gcry_strerror(err));
		_cr_aes_cleanup(handle, mac, *ciphertext, NULL, hmac);
		return 1;
	}

	// Check pkcs_padding
	*pkcs7_padding=*ciphertext[0];
	for (i = 0; i<*pkcs7_padding; i++) {
		if ((*ciphertext)[i]!=*pkcs7_padding) {
			*pkcs7_padding=0;
			break;
		}
	}

	_cr_aes_cleanup(handle, mac, NULL, NULL, hmac);

	return 0;
}
