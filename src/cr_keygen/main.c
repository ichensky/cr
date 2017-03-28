#include <stdio.h>
#include "../cr/file.h"
#include "../cr/rsa.h"
#include "../cr_data/cr.h"

void cr_keygen_keygen(const char *fname,const size_t fname_len){
	char* fnamep; 
	char* fnames;
	
	unsigned char *public_key;
	unsigned char *private_key;
	size_t public_key_len;
	size_t private_key_len;

	

	cr_rsa_cert_file_names(fname,fname_len,&fnamep,&fnames);
	cr_rsa_key_gen(&public_key,&public_key_len,&private_key,&private_key_len);

	cr_file_write_buf_to_file(fnamep, public_key, public_key_len);
	cr_file_write_buf_to_file(fnames, private_key, private_key_len);

	free(public_key);
	free(private_key);

	//unsigned char *sign_data;
	//size_t sign_data_len;
//
	//unsigned char *text=(unsigned char *)"Hello world";
	//printf("str: %s\n",text);
	//size_t  text_len=strlen((char *)text);
	//unsigned char *packed_data;
	//size_t  packed_data_len;
	//cr_rsa_encrypt(public_key,public_key_len,text,text_len,&packed_data,&packed_data_len);
//
	//unsigned char *text_dec;
	//size_t text_dec_len;
	//cr_rsa_decrypt(private_key,private_key_len,packed_data,packed_data_len,
	//&text_dec,&text_dec_len);
	//printf("decstr: %s\n",text_dec);
//
//
//// sign msg
		//cr_rsa_sign(private_key,private_key_len,text_dec,text_dec_len,&sign_data,&sign_data_len);
	//printf("signed msg: %s\n",sign_data);
//// vefify msg
		//size_t result;
	//result=cr_rsa_verify(public_key,public_key_len,text_dec,text_dec_len,sign_data,sign_data_len);
	//printf("verify result:%d\n",(int)result);
//
	//free(sign_data);

	
	
	//free(packed_data);
	//free(text_dec);
}
int main (int argc, const char **argv) {
	size_t fname_len;

	fname_len=strlen(cr_data_key_fname);

	printf("RSA key generation ..\n");
	cr_keygen_keygen(cr_data_key_fname,fname_len);
	return(0);
}

//#include "../cr/hash.h"
//void cr_app_gen_hash(){
//char *str="hello world";
//size_t str_len=strlen(str)+1;
//unsigned char *hash;
//size_t hash_len;
//size_t i;
//cr_hash_calc((const unsigned char *)str,str_len,&hash,&hash_len);
//
//printf("str: %s\n",str);
//printf("hash: ");
//for(i=0;i<hash_len;i++){
//printf("%c",hash[i]);
//}
//printf("\n");
//
//free(hash);
//} 
