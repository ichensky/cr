#include<gcrypt.h>

void cr_hash_calc(const int algo,
		  const unsigned char *str,
		  const size_t str_len,
		  unsigned char **hash,
		  size_t *hash_len);

void cr_hash_calc_64(const unsigned char *str,
		     const size_t str_len,
		     unsigned char **hash,
		     size_t *hash_len);

void cr_hash_calc_32(const unsigned char *str,
		     const size_t str_len,
		     unsigned char **hash,
		     size_t *hash_len);
