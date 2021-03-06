#include "random.h"

void cr_random_fill(const size_t buffer_len, unsigned char **buffer){
	*buffer=calloc(buffer_len,sizeof(unsigned char));
	gcry_randomize(*buffer,buffer_len,GCRY_VERY_STRONG_RANDOM);
}

void cr_random_fill_with_nums_chars(const size_t buffer_len, unsigned char **buffer){
	unsigned char *bb;
	bb=malloc(sizeof(unsigned char)*buffer_len);
	cr_random_fill(buffer_len,buffer);
	cr_random_fill(buffer_len,&bb);

	size_t i,k;
	for(i=0;i<buffer_len;i++){
		k=((size_t)(bb[i]))%3;
		if(k==0){
		(*buffer)[i]=(unsigned char)(65+((size_t)((*buffer)[i]))%26);
		}else if(k==1){
		(*buffer)[i]=(unsigned char)(97+((size_t)((*buffer)[i]))%26);
		}else{
		(*buffer)[i]=(unsigned char)(48+((size_t)((*buffer)[i]))%10);
		}
	}
}
size_t cr_random_fill_with_nums_chars_in_range(const ssize_t min,
					       const ssize_t max,
					       unsigned char **buffer,
					       size_t *buffer_len){
	if (min>max||min<0||max>255) {
		return 1;
	}
	*buffer_len=cr_random_number_256(18,32);
	cr_random_fill_with_nums_chars(*buffer_len,buffer);

	return 0;
};

size_t cr_random_number_256(const size_t min, const size_t max){
	size_t len=1,
		number;
	unsigned char *buffer;
	len=sizeof(size_t);
	buffer=malloc(sizeof(unsigned char)*len);
	cr_random_fill(len,&buffer);
	number=min+((size_t)buffer[0])%(max+1-min);
	free(buffer);

	return number;
}
