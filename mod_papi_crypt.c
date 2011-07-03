#include <mcrypt.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/des.h>
#include <openssl/pem.h>
#include "mod_papi_private.h"

char           *
papi_encrypt_AES(request_rec * r, char *input, char *_key, int keylenbits)
{
	char           *module_name = apr_psprintf(r->pool, "rijndael-%d", keylenbits);
	MCRYPT          td;
	if ((td = mcrypt_module_open(module_name, NULL, "ecb", NULL)) == MCRYPT_FAILED) {
		APACHE_LOG(APLOG_ERR, "papi_encrypt_AES::mcrypt_module_open");
		return NULL;
	}
	int             length = strlen(input);
	char           *key = apr_pstrndup(r->pool, _key, mcrypt_enc_get_key_size(td));
	int             blocksize = mcrypt_enc_get_block_size(td);
	int             datasize = (((length - 1) / blocksize) + 1) * blocksize;
	char           *blockbuffer = apr_pcalloc(r->pool, datasize);
	memcpy(blockbuffer, input, length);

	//In ECB, VI is ignored
		int             err = 0;
	if (mcrypt_generic_init(td, key, strlen(key), NULL) != -1) {
		err = mcrypt_generic(td, blockbuffer, datasize);
		mcrypt_generic_deinit(td);
	}
	mcrypt_module_close(td);

	char           *output = NULL;
	if (err == 0) {
		output = apr_pcalloc(r->pool, apr_base64_encode_len(datasize));
		apr_base64_encode(output, blockbuffer, datasize);
	}
	APACHE_LOG(APLOG_DEBUG, "crypt KEY: %s OUTPUT: %s", key, output);

	return output;
}

char           *
papi_decrypt_AES(request_rec * r, char *_input, char *_key, int keylenbits)
{
	MCRYPT          td;
	int             err = -1;

	char           *input = apr_pcalloc(r->pool, apr_base64_decode_len(_input));
	int             length = apr_base64_decode(input, _input);


	char           *module_name = apr_psprintf(r->pool, "rijndael-%d", keylenbits);
	if ((td = mcrypt_module_open(module_name, NULL, "ecb", NULL)) == MCRYPT_FAILED) {
		APACHE_LOG(APLOG_ERR, "papi_decrypt_AES::mcrypt_module_open");
		return NULL;
	}
	char           *key = apr_pstrndup(r->pool, _key, mcrypt_enc_get_key_size(td));

	int             blocksize = mcrypt_enc_get_block_size(td);
	int             datasize = (((length - 1) / blocksize) + 1) * blocksize;

	char           *blockbuffer = apr_pcalloc(r->pool, datasize + 1);
	memcpy(blockbuffer, input, datasize);

	//In ECB, VI is ignored

		if (mcrypt_generic_init(td, key, strlen(key), NULL) != -1) {
		err = mdecrypt_generic(td, blockbuffer, datasize);
		mcrypt_generic_deinit(td);
	}
	mcrypt_module_close(td);

	return blockbuffer;
}

static EVP_PKEY *
papi_load_key(char *file, int format, char *pass)
{

	BIO            *key = NULL;
	EVP_PKEY       *pkey = NULL;

	if (file == NULL)
		return NULL;

	key = BIO_new(BIO_s_file());

	if (key == NULL)
		return NULL;

	if (BIO_read_filename(key, file) > 0) {
		if (format == FORMAT_ASN1)
			pkey = d2i_PrivateKey_bio(key, NULL);
		else if (format == FORMAT_PEM)
			pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, pass);
		else if (format == FORMAT_PKCS12) {
			PKCS12         *p12 = d2i_PKCS12_bio(key, NULL);
			PKCS12_parse(p12, pass, &pkey, NULL, NULL);
			PKCS12_free(p12);
			p12 = NULL;
		}
	}
	BIO_free(key);
	return pkey;
}

static EVP_PKEY *
papi_load_pubkey(char *file, int format)
{

	BIO            *key = NULL;
	EVP_PKEY       *pkey = NULL;

	if (file == NULL)
		return NULL;

	key = BIO_new(BIO_s_file());

	if (key == NULL)
		return NULL;

	if (BIO_read_filename(key, file) > 0) {
		if (format == FORMAT_ASN1)
			pkey = d2i_PUBKEY_bio(key, NULL);
		else if (format == FORMAT_PEM)
			pkey = PEM_read_bio_PUBKEY(key, NULL, NULL, NULL);
	}
	BIO_free(key);
	return (pkey);
}

char           *
papi_encrypt_priv_RSA(request_rec * r, char *rsa_in, char *keyfile)
{
	EVP_PKEY       *pkey = papi_load_key(keyfile, FORMAT_PEM, NULL);
	papi_return_val_if_fail(pkey, "ERRORFILE");
	apr_pool_cleanup_register(r->pool, pkey, (void *) EVP_PKEY_free, apr_pool_cleanup_null);

	RSA            *rsa = EVP_PKEY_get1_RSA(pkey);
	papi_return_val_if_fail(rsa, "ERRORFILE");
	apr_pool_cleanup_register(r->pool, rsa, (void *) RSA_free, apr_pool_cleanup_null);

	int             keysize = RSA_size(rsa);
	int             blockLength = keysize - 11;
	int             flen = strlen(rsa_in);
	int             n = 0;
	int             rsa_inlen = strlen(rsa_in);
	char           *rsa_out = NULL;
	apr_pool_cleanup_register(r->pool, rsa_out, (void *) free, apr_pool_cleanup_null);
	int             rsa_outlen = 0;
	int             totalsize = 0;

	do {
		rsa_inlen = strlen(&rsa_in[n]);
		rsa_inlen = (rsa_inlen > blockLength) ? blockLength : rsa_inlen;

		if (rsa_inlen <= 0) {
			APACHE_LOG(APLOG_ERR, "Input empty: rsa_inlen=%d,blockLength=%d,flen=%d",
				   rsa_inlen, blockLength, flen);
			return apr_pstrdup(r->pool, "ERRORCRYPT");
		}
		rsa_out = (char *) realloc(rsa_out, sizeof(unsigned char) * (totalsize + keysize + 5));

		if (rsa_out == NULL) {
			APACHE_LOG(APLOG_ERR, "Error reallocating memory");
			return apr_pstrdup(r->pool, "ERRORCRYPT");
		}
		rsa_outlen = RSA_private_encrypt(rsa_inlen, (unsigned char *) &rsa_in[n], (unsigned char *) &rsa_out[totalsize], rsa, RSA_PKCS1_PADDING);

		if (rsa_outlen != keysize) {
			APACHE_LOG(APLOG_ERR, "Length of rsa_out != keysize");
			return apr_pstrdup(r->pool, "ERRORCRYPT");
		}
		n += rsa_inlen;
		totalsize += rsa_outlen;
	} while (n < flen);

	rsa_out[totalsize] = '\0';

	char           *out = apr_pcalloc(r->pool, apr_base64_encode_len(totalsize) + 1);
	apr_base64_encode(out, rsa_out, totalsize);
	return out;
}

char           *
papi_decrypt_pub_RSA(request_rec * r, char *in, char *keyfile)
{
	int             blockLength;
	int             flen;
	int             keysize;
	int             n = 0;
	char           *out = NULL;
	EVP_PKEY       *pkey = NULL;
	RSA            *rsa = NULL;
	char           *rsa_in = NULL;
	int             rsa_inlen;
	int             rsa_outlen = 0;
	int             totalsize = 0;

	pkey = papi_load_pubkey(keyfile, FORMAT_PEM);
	if (!pkey)
		return apr_pstrdup(r->pool, "ERRORFILE");
	apr_pool_cleanup_register(r->pool, pkey, (void *) EVP_PKEY_free, apr_pool_cleanup_null);

	rsa = EVP_PKEY_get1_RSA(pkey);
	if (!rsa)
		return apr_pstrdup(r->pool, "ERRORFILE2");
	apr_pool_cleanup_register(r->pool, rsa, (void *) RSA_free, apr_pool_cleanup_null);

	rsa_in = apr_pcalloc(r->pool, apr_base64_decode_len(in) + 1);
	flen = apr_base64_decode(rsa_in, in);

	keysize = RSA_size(rsa);
	blockLength = keysize;

	apr_pool_cleanup_register(r->pool, out, (void *) free, apr_pool_cleanup_null);
	do {
		rsa_inlen = flen - n;
		rsa_inlen = (rsa_inlen > blockLength) ? blockLength : rsa_inlen;
		if (rsa_inlen <= 0) {
			APACHE_LOG(APLOG_ERR, "Input empty, rsa_inlen=%d,blockLength=%d,flen=%d",
				   rsa_inlen, blockLength, flen);
			return apr_pstrdup(r->pool, "ERRORCRYPT");
		}
		out = (char *) realloc(out, sizeof(char) * (totalsize + keysize + 5));
		if (out == NULL) {
			APACHE_LOG(APLOG_ERR, "Error reallocating memory");
			return apr_pstrdup(r->pool, "ERRORCRYPT");
		}
		rsa_outlen = RSA_public_decrypt(rsa_inlen, (unsigned char *) &rsa_in[n], (unsigned char *) &out[totalsize], rsa, RSA_PKCS1_PADDING);
		if (rsa_outlen > keysize) {
			APACHE_LOG(APLOG_ERR, "Length of rsa_out > keysize");
			return apr_pstrdup(r->pool, "ERRORCRYPT");
		}
		n += rsa_inlen;
		totalsize += rsa_outlen;
	} while (n < flen);

	out[totalsize] = '\0';

	return out;
}
