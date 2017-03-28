#include <stdlib.h>

void build_decoding_table();
size_t base64_cals_encode_len (const size_t data_len);
void base64_encode(const unsigned char *data,
		   const size_t data_len,
		   const size_t encoded_data_len,
		   char *encoded_data);
size_t base64_cals_decode_len (const char *encoded_data,
			       const size_t encoded_data_len);
void base64_decode(const char *encoded_data,
		   const size_t encoded_data_len,
		   const size_t decoded_data_len,
		   unsigned char *decoded_data);
void base64_cleanup();
