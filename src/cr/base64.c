#include <stdint.h>
#include "base64.h"

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
				'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
				'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
				'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
				'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
				'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
				'w', 'x', 'y', 'z', '0', '1', '2', '3',
				'4', '5', '6', '7', '8', '9', '+', '/'};

static char *decoding_table = NULL;
static size_t mod_table[] = {0, 2, 1};


void build_decoding_table() {
	size_t i;

	decoding_table = malloc(256);

	for (i = 0; i < 64; i++){
		decoding_table[(unsigned char) encoding_table[i]] = i;
	}
}

size_t base64_cals_encode_len (const size_t data_len){
	return 4 * ((data_len + 2) / 3);
}

void base64_encode(const unsigned char *data,
		   const size_t data_len,
		   const size_t encoded_data_len,
		   char *encoded_data) {
	size_t i,j;

	for (i = 0, j = 0; i < data_len;) {

		uint32_t octet_a=i<data_len?(unsigned char)data[i++]:0;
		uint32_t octet_b=i<data_len?(unsigned char)data[i++]:0;
		uint32_t octet_c=i<data_len?(unsigned char)data[i++]:0;

		uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

		encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
		encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
	}

	for (i = 0; i < mod_table[data_len % 3]; i++){
		encoded_data[encoded_data_len - 1 - i] = '=';
	}
}


size_t base64_cals_decode_len (const char *encoded_data,
			       const size_t encoded_data_len){

	size_t decoded_data_len;
	decoded_data_len=encoded_data_len / 4 * 3;
	if (encoded_data[encoded_data_len- 1] == '=') (decoded_data_len)--;
	if (encoded_data[encoded_data_len- 2] == '=') (decoded_data_len)--;

	return decoded_data_len;
}
void base64_decode(const char *encoded_data,
		   const size_t encoded_data_len,
		   const size_t decoded_data_len,
		   unsigned char *decoded_data) {

	size_t i,j;
	if (decoding_table == NULL) build_decoding_table();

	for (i = 0, j = 0; i < encoded_data_len;) {
		uint32_t sextet_a = encoded_data[i] == '='
			? 0 & i++ : (uint32_t)decoding_table[(size_t)encoded_data[i++]];
		uint32_t sextet_b = encoded_data[i] == '='
			? 0 & i++ : (uint32_t)decoding_table[(size_t)encoded_data[i++]];
		uint32_t sextet_c = encoded_data[i] == '='
			? 0 & i++ : (uint32_t)decoding_table[(size_t)encoded_data[i++]];
		uint32_t sextet_d = encoded_data[i] == '='
			? 0 & i++ : (uint32_t)decoding_table[(size_t)encoded_data[i++]];

		uint32_t triple = (sextet_a << 3 * 6)
			+ (sextet_b << 2 * 6)
			+ (sextet_c << 1 * 6)
			+ (sextet_d << 0 * 6);

		if (j < decoded_data_len) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
		if (j < decoded_data_len) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
		if (j < decoded_data_len) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
	}
}

void base64_cleanup() {
	free(decoding_table);
}
