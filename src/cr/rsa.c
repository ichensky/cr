#include "rsa.h"

size_t cr_rsa_key_gen(unsigned char **public_key,
		      size_t *public_key_len,
		      unsigned char **private_key,
		      size_t *private_key_len){

	gcry_error_t err = 0;
	gcry_sexp_t rsa_parms;
	gcry_sexp_t rsa_keypair;
	
	gcry_sexp_t rsa_skey=NULL;
	gcry_sexp_t rsa_pkey=NULL;

	/* Generate a new RSA key pair. */
	err = gcry_sexp_build(&rsa_parms, NULL, "(genkey (rsa (nbits 4:4096)(rsa-use-e 1:1)))");
	if (err) {
		//xerr("gcrypt: failed to create rsa params");
		return 1;
	}

	err = gcry_pk_genkey(&rsa_keypair, rsa_parms);
	gcry_sexp_release(rsa_parms);
	if (err) {
		//xerr("gcrypt: failed to create rsa key pair");
		return 1;
	}
	
	rsa_pkey=gcry_sexp_find_token(rsa_keypair,"public-key",0);
	rsa_skey=gcry_sexp_find_token(rsa_keypair,"private-key",0);
	gcry_sexp_release(rsa_keypair);

	
	*public_key_len=gcry_sexp_sprint(rsa_pkey,GCRYSEXP_FMT_CANON,NULL,0);
	*public_key=malloc(*public_key_len*sizeof(char));
	*public_key_len=gcry_sexp_sprint(rsa_pkey,GCRYSEXP_FMT_CANON,*public_key,*public_key_len);
	gcry_sexp_release(rsa_pkey);

	*private_key_len=gcry_sexp_sprint(rsa_skey,GCRYSEXP_FMT_CANON,NULL,0);
	*private_key=malloc(*private_key_len*sizeof(char));
	*private_key_len=gcry_sexp_sprint(rsa_skey,GCRYSEXP_FMT_CANON,*private_key,*private_key_len);
	gcry_sexp_release(rsa_skey);


	return 0;
	
}

void cr_rsa_cert_file_names(const char *fname,
			    const size_t fname_len,
			    char **fnamep,
			    char **fnames){
	
	*fnamep=calloc(fname_len+2,sizeof(char));
	*fnames=calloc(fname_len+2,sizeof(char));
	sprintf(*fnamep,"%sp",fname);
	sprintf(*fnames,"%ss",fname);
}

size_t cr_rsa_encrypt(const unsigned char *public_key,
		      const size_t public_key_len,
		      const unsigned char *text,
		      const size_t text_len,
		      unsigned char **packed_data,
		      size_t *packed_data_len
	){

	gcry_error_t err;
	gcry_sexp_t rsa_keypair,
		rsa_pkey,
		data,
		ciph;
	gcry_mpi_t msg;

	err = gcry_sexp_new(&rsa_keypair, public_key, public_key_len, 0);
	rsa_pkey=gcry_sexp_find_token(rsa_keypair,"public-key",0);
	gcry_sexp_release(rsa_keypair);

	/* Create a message. */
	err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, text,
			    text_len, NULL);
	if (err) {
		//xerr("failed to create a mpi from the message");
		return 1;
	}
	err = gcry_sexp_build(&data, NULL,"(data (flags raw) (value %m))", msg);
	gcry_mpi_release(msg);
	if (err) {
		//xerr("failed to create a sexp from the message");
		return 1;
	}

	/* Encrypt the message. */
	err = gcry_pk_encrypt(&ciph, data, rsa_pkey);
	gcry_sexp_release(data);
	gcry_sexp_release(rsa_pkey);
	if (err) {
		//xerr("gcrypt: encryption failed");
		return 1;
	}

	*packed_data_len=gcry_sexp_sprint(ciph,GCRYSEXP_FMT_CANON,NULL,0);
	if(*packed_data_len==0){
		return 1;
	}
	*packed_data=malloc(*packed_data_len*sizeof(unsigned char));
	gcry_sexp_sprint(ciph,GCRYSEXP_FMT_CANON,*packed_data,*packed_data_len);
	gcry_sexp_release(ciph);

	return 0;
}


size_t cr_rsa_decrypt(const unsigned char *private_key,
		      const size_t private_key_len,
		      const unsigned char *packed_data,
		      const size_t packed_data_len,
		      unsigned char **text,
		      size_t *text_len){

	gcry_error_t err;
	
	gcry_sexp_t rsa_keypair,
		rsa_skey,
		data,
		plain;

	gcry_mpi_t msg;


	err = gcry_sexp_new(&rsa_keypair, private_key, private_key_len, 0);
	rsa_skey=gcry_sexp_find_token(rsa_keypair,"private-key",0);
	gcry_sexp_release(rsa_keypair);

	err = gcry_sexp_new(&data, packed_data,packed_data_len, 0);
	if (err) {
		return 1;
	}

	err = gcry_pk_decrypt(&plain,data, rsa_skey);
	gcry_sexp_release(data);
	gcry_sexp_release(rsa_skey);
	if (err) {
		//printf("gcrypt: decryption failed\n");
		return 1;
	}

	msg=gcry_sexp_nth_mpi(plain,0,GCRYMPI_FMT_USG);
	gcry_sexp_release(plain);

	err=gcry_mpi_print(GCRYMPI_FMT_USG,NULL,0,text_len,msg);
	if (err) {
		return 1;
	}
	*text=malloc(*text_len*sizeof(unsigned char));
	err=gcry_mpi_print(GCRYMPI_FMT_USG,*text,*text_len,0,msg);
	gcry_mpi_release(msg);
	if (err) {
		return 1;
	}

	return 0;
}


size_t cr_rsa_sign(const unsigned char *private_key,
		   const size_t private_key_len,
		   const unsigned char *data,
		   const size_t data_len,
		   unsigned char **sign_data,
		   size_t *sign_data_len){
	gcry_error_t err;
	
	gcry_sexp_t rsa_keypair,
		rsa_skey,
		retsexp,
		r_sig;


	err = gcry_sexp_new(&rsa_keypair, private_key, private_key_len, 0);
	rsa_skey=gcry_sexp_find_token(rsa_keypair,"private-key",0);
	gcry_sexp_release(rsa_keypair);

	err = gcry_sexp_new(&retsexp, data,data_len, 0);
	if (err) {
		return 1;
	}

	err=gcry_pk_sign(&r_sig,retsexp,rsa_skey);
	gcry_sexp_release(retsexp);
	if (err) {
		return 1;
	}
	

	*sign_data_len=gcry_sexp_sprint(r_sig,GCRYSEXP_FMT_CANON,NULL,0);
	if(*sign_data_len==0){
		return 1;
	}
	*sign_data=malloc(*sign_data_len*sizeof(unsigned char));
	gcry_sexp_sprint(r_sig,GCRYSEXP_FMT_CANON,*sign_data,*sign_data_len);
	gcry_sexp_release(r_sig);
	return 0;
}

size_t cr_rsa_verify(const unsigned char *public_key,
		     const size_t public_key_len,
		     const unsigned char *data,
		     const size_t data_len,
		     const unsigned char *sign_data,
		     const size_t sign_data_len){

	gcry_error_t err;
	
	gcry_sexp_t rsa_keypair,
		rsa_pkey,
		retsexp,
		r_sig;


	err = gcry_sexp_new(&rsa_keypair, public_key, public_key_len, 0);
	rsa_pkey=gcry_sexp_find_token(rsa_keypair,"public-key",0);
	gcry_sexp_release(rsa_keypair);

	err = gcry_sexp_new(&retsexp, data,data_len, 0);
	if (err) {
		return 1;
	}

	err = gcry_sexp_new(&r_sig, sign_data,sign_data_len, 0);
	if (err) {
		return 1;
	}
	
	err = gcry_pk_verify(r_sig, retsexp,rsa_pkey);
	if (err) {
		return 1;
	}

	return 0;
}
