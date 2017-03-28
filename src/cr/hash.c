#include "hash.h"

void cr_hash_calc(const int algo,
		  const unsigned char *str,
		  const size_t str_len,
		  unsigned char **hash,
		  size_t *hash_len){

	*hash_len=gcry_md_get_algo_dlen(algo);
	*hash=calloc(*hash_len,sizeof(unsigned char));
	gcry_md_hash_buffer(algo,*hash,str,str_len);
}


void cr_hash_calc_64(const unsigned char *str,
		     const size_t str_len,
		     unsigned char **hash,
		     size_t *hash_len){

	int algo=GCRY_MD_SHA512; // 64-bit
	cr_hash_calc(algo,str,str_len,hash,hash_len);
}

void cr_hash_calc_32(const unsigned char *str,
		     const size_t str_len,
		     unsigned char **hash,
		     size_t *hash_len){

	int algo=GCRY_MD_SHA256; // 64-bit
	cr_hash_calc(algo,str,str_len,hash,hash_len);
}
