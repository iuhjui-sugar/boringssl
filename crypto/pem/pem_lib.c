/* crypto/pem/pem_lib.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.] */

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include <openssl/base64.h>
#include <openssl/buf.h>
#include <openssl/des.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include "../evp/internal.h"


#define MIN_LENGTH	4

static int load_iv(char **fromp,unsigned char *to, int num);
static int check_pem(const char *nm, const char *name);
int pem_check_suffix(const char *pem_str, const char *suffix);

void PEM_proc_type(char *buf, int type)
	{
	const char *str;

	if (type == PEM_TYPE_ENCRYPTED)
		str="ENCRYPTED";
	else if (type == PEM_TYPE_MIC_CLEAR)
		str="MIC-CLEAR";
	else if (type == PEM_TYPE_MIC_ONLY)
		str="MIC-ONLY";
	else
		str="BAD-TYPE";
		
	BUF_strlcat(buf,"Proc-Type: 4,",PEM_BUFSIZE);
	BUF_strlcat(buf,str,PEM_BUFSIZE);
	BUF_strlcat(buf,"\n",PEM_BUFSIZE);
	}

void PEM_dek_info(char *buf, const char *type, int len, char *str)
	{
	static const unsigned char map[17]="0123456789ABCDEF";
	long i;
	int j;

	BUF_strlcat(buf,"DEK-Info: ",PEM_BUFSIZE);
	BUF_strlcat(buf,type,PEM_BUFSIZE);
	BUF_strlcat(buf,",",PEM_BUFSIZE);
	j=strlen(buf);
	if (j + (len * 2) + 1 > PEM_BUFSIZE)
        	return;
	for (i=0; i<len; i++)
		{
		buf[j+i*2]  =map[(str[i]>>4)&0x0f];
		buf[j+i*2+1]=map[(str[i]   )&0x0f];
		}
	buf[j+i*2]='\n';
	buf[j+i*2+1]='\0';
	}

#ifndef OPENSSL_NO_FP_API
void *PEM_ASN1_read(d2i_of_void *d2i, const char *name, FILE *fp, void **x,
		    pem_password_cb *cb, void *u)
	{
        BIO *b;
        void *ret;

        if ((b=BIO_new(BIO_s_file())) == NULL)
		{
		OPENSSL_PUT_ERROR(PEM, PEM_ASN1_read, ERR_R_BUF_LIB);
                return(0);
		}
        BIO_set_fp(b,fp,BIO_NOCLOSE);
        ret=PEM_ASN1_read_bio(d2i,name,b,x,cb,u);
        BIO_free(b);
        return(ret);
	}
#endif

static int check_pem(const char *nm, const char *name)
{
	/* Normal matching nm and name */
	if (!strcmp(nm,name)) return 1;

	/* Make PEM_STRING_EVP_PKEY match any private key */

	if(!strcmp(name,PEM_STRING_EVP_PKEY))
		{
		int slen;
		const EVP_PKEY_ASN1_METHOD *ameth;
		if(!strcmp(nm,PEM_STRING_PKCS8))
			return 1;
		if(!strcmp(nm,PEM_STRING_PKCS8INF))
			return 1;
		slen = pem_check_suffix(nm, "PRIVATE KEY"); 
		if (slen > 0)
			{
			/* NB: ENGINE implementations wont contain
			 * a deprecated old private key decode function
			 * so don't look for them.
			 */
			ameth = EVP_PKEY_asn1_find_str(NULL, nm, slen);
			if (ameth && ameth->old_priv_decode)
				return 1;
			}
		return 0;
		}

	if(!strcmp(name,PEM_STRING_PARAMETERS))
		{
		int slen;
		const EVP_PKEY_ASN1_METHOD *ameth;
		slen = pem_check_suffix(nm, "PARAMETERS"); 
		if (slen > 0)
			{
			ENGINE *e;
			ameth = EVP_PKEY_asn1_find_str(&e, nm, slen);
			if (ameth)
				{
				int r;
				if (ameth->param_decode)
					r = 1;
				else
					r = 0;
				return r;
				}
			}
		return 0;
		}
	/* If reading DH parameters handle X9.42 DH format too */
	if(!strcmp(nm,PEM_STRING_DHXPARAMS) &&
		!strcmp(name,PEM_STRING_DHPARAMS)) return 1;

	/* Permit older strings */

	if(!strcmp(nm,PEM_STRING_X509_OLD) &&
		!strcmp(name,PEM_STRING_X509)) return 1;

	if(!strcmp(nm,PEM_STRING_X509_REQ_OLD) &&
		!strcmp(name,PEM_STRING_X509_REQ)) return 1;

	/* Allow normal certs to be read as trusted certs */
	if(!strcmp(nm,PEM_STRING_X509) &&
		!strcmp(name,PEM_STRING_X509_TRUSTED)) return 1;

	if(!strcmp(nm,PEM_STRING_X509_OLD) &&
		!strcmp(name,PEM_STRING_X509_TRUSTED)) return 1;

	/* Some CAs use PKCS#7 with CERTIFICATE headers */
	if(!strcmp(nm, PEM_STRING_X509) &&
		!strcmp(name, PEM_STRING_PKCS7)) return 1;

	if(!strcmp(nm, PEM_STRING_PKCS7_SIGNED) &&
		!strcmp(name, PEM_STRING_PKCS7)) return 1;

#ifndef OPENSSL_NO_CMS
	if(!strcmp(nm, PEM_STRING_X509) &&
		!strcmp(name, PEM_STRING_CMS)) return 1;
	/* Allow CMS to be read from PKCS#7 headers */
	if(!strcmp(nm, PEM_STRING_PKCS7) &&
		!strcmp(name, PEM_STRING_CMS)) return 1;
#endif

	return 0;
}

int PEM_bytes_read_bio(unsigned char **pdata, long *plen, char **pnm, const char *name, BIO *bp,
	     pem_password_cb *cb, void *u)
	{
	EVP_CIPHER_INFO cipher;
	char *nm=NULL,*header=NULL;
	unsigned char *data=NULL;
	long len;
	int ret = 0;

	for (;;)
		{
		if (!PEM_read_bio(bp,&nm,&header,&data,&len)) {
			if(ERR_GET_REASON(ERR_peek_error()) ==
				PEM_R_NO_START_LINE)
				ERR_add_error_data(2, "Expecting: ", name);
			return 0;
		}
		if(check_pem(nm, name)) break;
		OPENSSL_free(nm);
		OPENSSL_free(header);
		OPENSSL_free(data);
		}
	if (!PEM_get_EVP_CIPHER_INFO(header,&cipher)) goto err;
	if (!PEM_do_header(&cipher,data,&len,cb,u)) goto err;

	*pdata = data;
	*plen = len;

	if (pnm)
		*pnm = nm;

	ret = 1;

err:
	if (!ret || !pnm) OPENSSL_free(nm);
	OPENSSL_free(header);
	if (!ret) OPENSSL_free(data);
	return ret;
	}

#ifndef OPENSSL_NO_FP_API
int PEM_ASN1_write(i2d_of_void *i2d, const char *name, FILE *fp,
		   void *x, const EVP_CIPHER *enc, unsigned char *kstr,
		   int klen, pem_password_cb *callback, void *u)
        {
        BIO *b;
        int ret;

        if ((b=BIO_new(BIO_s_file())) == NULL)
		{
		OPENSSL_PUT_ERROR(PEM, PEM_ASN1_write, ERR_R_BUF_LIB);
                return(0);
		}
        BIO_set_fp(b,fp,BIO_NOCLOSE);
        ret=PEM_ASN1_write_bio(i2d,name,b,x,enc,kstr,klen,callback,u);
        BIO_free(b);
        return(ret);
        }
#endif

int PEM_ASN1_write_bio(i2d_of_void *i2d, const char *name, BIO *bp,
		       void *x, const EVP_CIPHER *enc, unsigned char *kstr,
		       int klen, pem_password_cb *callback, void *u)
	{
	EVP_CIPHER_CTX ctx;
	int dsize=0,i,j,ret=0;
	unsigned char *p,*data=NULL;
	const char *objstr=NULL;
	char buf[PEM_BUFSIZE];
	unsigned char key[EVP_MAX_KEY_LENGTH];
	unsigned char iv[EVP_MAX_IV_LENGTH];
	
	if (enc != NULL)
		{
		objstr=OBJ_nid2sn(EVP_CIPHER_nid(enc));
		if (objstr == NULL)
			{
			OPENSSL_PUT_ERROR(PEM, PEM_ASN1_write_bio, PEM_R_UNSUPPORTED_CIPHER);
			goto err;
			}
		}

	if ((dsize=i2d(x,NULL)) < 0)
		{
		OPENSSL_PUT_ERROR(PEM, PEM_ASN1_write_bio, ERR_R_ASN1_LIB);
		dsize=0;
		goto err;
		}
	/* dzise + 8 bytes are needed */
	/* actually it needs the cipher block size extra... */
	data=(unsigned char *)OPENSSL_malloc((unsigned int)dsize+20);
	if (data == NULL)
		{
		OPENSSL_PUT_ERROR(PEM, PEM_ASN1_write_bio, ERR_R_MALLOC_FAILURE);
		goto err;
		}
	p=data;
	i=i2d(x,&p);

	if (enc != NULL)
		{
		const unsigned iv_len = EVP_CIPHER_iv_length(enc);

		if (kstr == NULL)
			{
			klen = 0;
			if (!callback)
				callback = PEM_def_callback;
 			klen=(*callback)(buf,PEM_BUFSIZE,1,u);
			if (klen <= 0)
				{
				OPENSSL_PUT_ERROR(PEM, PEM_ASN1_write_bio, PEM_R_READ_KEY);
				goto err;
				}
			kstr=(unsigned char *)buf;
			}
		assert(iv_len <= (int)sizeof(iv));
		if (!RAND_bytes(iv, iv_len)) /* Generate a salt */
			goto err;
		/* The 'iv' is used as the iv and as a salt.  It is
		 * NOT taken from the BytesToKey function */
		if (!EVP_BytesToKey(enc,EVP_md5(),iv,kstr,klen,1,key,NULL))
			goto err;

		if (kstr == (unsigned char *)buf) OPENSSL_cleanse(buf,PEM_BUFSIZE);

		assert(strlen(objstr)+23+2*iv_len+13 <= sizeof buf);

		buf[0]='\0';
		PEM_proc_type(buf,PEM_TYPE_ENCRYPTED);
		PEM_dek_info(buf,objstr,iv_len,(char *)iv);
		/* k=strlen(buf); */

		EVP_CIPHER_CTX_init(&ctx);
		ret = 1;
		if (!EVP_EncryptInit_ex(&ctx,enc,NULL,key,iv)
			|| !EVP_EncryptUpdate(&ctx,data,&j,data,i)
			|| !EVP_EncryptFinal_ex(&ctx,&(data[j]),&i))
			ret = 0;
		else
			i += j;
		EVP_CIPHER_CTX_cleanup(&ctx);
		if (ret == 0)
			goto err;
		}
	else
		{
		ret=1;
		buf[0]='\0';
		}
	i=PEM_write_bio(bp,name,buf,data,i);
	if (i <= 0) ret=0;
err:
	OPENSSL_cleanse(key,sizeof(key));
	OPENSSL_cleanse(iv,sizeof(iv));
	OPENSSL_cleanse((char *)&ctx,sizeof(ctx));
	OPENSSL_cleanse(buf,PEM_BUFSIZE);
	if (data != NULL)
		{
		OPENSSL_cleanse(data,(unsigned int)dsize);
		OPENSSL_free(data);
		}
	return(ret);
	}

int PEM_do_header(EVP_CIPHER_INFO *cipher, unsigned char *data, long *plen,
	     pem_password_cb *callback,void *u)
	{
	int i=0,j,o,klen;
	long len;
	EVP_CIPHER_CTX ctx;
	unsigned char key[EVP_MAX_KEY_LENGTH];
	char buf[PEM_BUFSIZE];

	len= *plen;

	if (cipher->cipher == NULL) return(1);

	klen = 0;
	if (!callback) callback = PEM_def_callback;
	klen=callback(buf,PEM_BUFSIZE,0,u);
	if (klen <= 0)
		{
		OPENSSL_PUT_ERROR(PEM, PEM_do_header, PEM_R_BAD_PASSWORD_READ);
		return(0);
		}

	if (!EVP_BytesToKey(cipher->cipher,EVP_md5(),&(cipher->iv[0]),
		(unsigned char *)buf,klen,1,key,NULL))
		return 0;

	j=(int)len;
	EVP_CIPHER_CTX_init(&ctx);
	o = EVP_DecryptInit_ex(&ctx,cipher->cipher,NULL, key,&(cipher->iv[0]));
	if (o)
		o = EVP_DecryptUpdate(&ctx,data,&i,data,j);
	if (o)
		o = EVP_DecryptFinal_ex(&ctx,&(data[i]),&j);
	EVP_CIPHER_CTX_cleanup(&ctx);
	OPENSSL_cleanse((char *)buf,sizeof(buf));
	OPENSSL_cleanse((char *)key,sizeof(key));
	if (!o)
		{
		OPENSSL_PUT_ERROR(PEM, PEM_do_header, PEM_R_BAD_DECRYPT);
		return(0);
		}
	j+=i;
	*plen=j;
	return(1);
	}

static const EVP_CIPHER* cipher_by_name(const char *name) {
  /* This is similar to the (deprecated) function
   * |EVP_get_cipherbyname|. */
  if (0 == strcmp(name, SN_rc4)) {
    return EVP_rc4();
  } else if (0 == strcmp(name, SN_des_cbc)) {
    return EVP_des_cbc();
  } else if (0 == strcmp(name, SN_des_ede3_cbc)) {
    return EVP_des_ede3_cbc();
  } else if (0 == strcmp(name, SN_aes_128_ecb)) {
    return EVP_aes_128_ecb();
  } else if (0 == strcmp(name, SN_aes_128_cbc)) {
    return EVP_aes_128_cbc();
  } else if (0 == strcmp(name, SN_aes_128_ctr)) {
    return EVP_aes_128_ctr();
  } else if (0 == strcmp(name, SN_aes_128_ofb128)) {
    return EVP_aes_128_ofb();
  } else if (0 == strcmp(name, SN_aes_256_ecb)) {
    return EVP_aes_256_ecb();
  } else if (0 == strcmp(name, SN_aes_256_cbc)) {
    return EVP_aes_256_cbc();
  } else if (0 == strcmp(name, SN_aes_256_ctr)) {
    return EVP_aes_256_ctr();
  } else if (0 == strcmp(name, SN_aes_256_ofb128)) {
    return EVP_aes_256_ofb();

    /* Deprecated */

  } else if (0 == strcmp(name, SN_aes_128_gcm)) {
    return EVP_aes_128_gcm();
  } else if (0 == strcmp(name, SN_aes_256_gcm)) {
    return EVP_aes_256_gcm();
  } else if (0 == strcmp(name, SN_aes_192_ecb)) {
    return EVP_aes_192_ecb();
  } else if (0 == strcmp(name, SN_aes_192_cbc)) {
    return EVP_aes_192_cbc();
  } else if (0 == strcmp(name, SN_aes_192_ctr)) {
    return EVP_aes_192_ctr();
  } else if (0 == strcmp(name, SN_aes_192_gcm)) {
    return EVP_aes_192_gcm();

    /* Even more deprecated */

  } else if (0 == strcmp(name, SN_rc2_40_cbc)) {
    return EVP_rc2_40_cbc();
  } else {
    return NULL;
  }
}

int PEM_get_EVP_CIPHER_INFO(char *header, EVP_CIPHER_INFO *cipher)
	{
	const EVP_CIPHER *enc=NULL;
	char *p,c;
	char **header_pp = &header;

	cipher->cipher=NULL;
	if ((header == NULL) || (*header == '\0') || (*header == '\n'))
		return(1);
	if (strncmp(header,"Proc-Type: ",11) != 0)
		{ OPENSSL_PUT_ERROR(PEM, PEM_get_EVP_CIPHER_INFO, PEM_R_NOT_PROC_TYPE); return(0); }
	header+=11;
	if (*header != '4') return(0); header++;
	if (*header != ',') return(0); header++;
	if (strncmp(header,"ENCRYPTED",9) != 0)
		{ OPENSSL_PUT_ERROR(PEM, PEM_get_EVP_CIPHER_INFO, PEM_R_NOT_ENCRYPTED); return(0); }
	for (; (*header != '\n') && (*header != '\0'); header++)
		;
	if (*header == '\0')
		{ OPENSSL_PUT_ERROR(PEM, PEM_get_EVP_CIPHER_INFO, PEM_R_SHORT_HEADER); return(0); }
	header++;
	if (strncmp(header,"DEK-Info: ",10) != 0)
		{ OPENSSL_PUT_ERROR(PEM, PEM_get_EVP_CIPHER_INFO, PEM_R_NOT_DEK_INFO); return(0); }
	header+=10;

	p=header;
	for (;;)
		{
		c= *header;
		if (!(	((c >= 'A') && (c <= 'Z')) || (c == '-') ||
			((c >= '0') && (c <= '9'))))
			break;
		header++;
		}
	*header='\0';
	cipher->cipher=enc=cipher_by_name(p);
	*header=c;
	header++;

	if (enc == NULL)
		{
		OPENSSL_PUT_ERROR(PEM, PEM_get_EVP_CIPHER_INFO, PEM_R_UNSUPPORTED_ENCRYPTION);
		return(0);
		}
	if (!load_iv(header_pp,&(cipher->iv[0]),EVP_CIPHER_iv_length(enc)))
		return(0);

	return(1);
	}

static int load_iv(char **fromp, unsigned char *to, int num)
	{
	int v,i;
	char *from;

	from= *fromp;
	for (i=0; i<num; i++) to[i]=0;
	num*=2;
	for (i=0; i<num; i++)
		{
		if ((*from >= '0') && (*from <= '9'))
			v= *from-'0';
		else if ((*from >= 'A') && (*from <= 'F'))
			v= *from-'A'+10;
		else if ((*from >= 'a') && (*from <= 'f'))
			v= *from-'a'+10;
		else
			{
			OPENSSL_PUT_ERROR(PEM, load_iv, PEM_R_BAD_IV_CHARS);
			return(0);
			}
		from++;
		to[i/2]|=v<<(long)((!(i&1))*4);
		}

	*fromp=from;
	return(1);
	}

#ifndef OPENSSL_NO_FP_API
int PEM_write(FILE *fp, const char *name, const char *header,
	      const unsigned char *data, long len)
        {
        BIO *b;
        int ret;

        if ((b=BIO_new(BIO_s_file())) == NULL)
		{
		OPENSSL_PUT_ERROR(PEM, PEM_write, ERR_R_BUF_LIB);
                return(0);
		}
        BIO_set_fp(b,fp,BIO_NOCLOSE);
        ret=PEM_write_bio(b, name, header, data,len);
        BIO_free(b);
        return(ret);
        }
#endif

int PEM_write_bio(BIO *bp, const char *name, const char *header,
		  const unsigned char *data, long len)
	{
	int nlen,n,i,j,outl;
	unsigned char *buf = NULL;
	EVP_ENCODE_CTX ctx;
	int reason=ERR_R_BUF_LIB;
	
	EVP_EncodeInit(&ctx);
	nlen=strlen(name);

	if (	(BIO_write(bp,"-----BEGIN ",11) != 11) ||
		(BIO_write(bp,name,nlen) != nlen) ||
		(BIO_write(bp,"-----\n",6) != 6))
		goto err;
		
	i=strlen(header);
	if (i > 0)
		{
		if (	(BIO_write(bp,header,i) != i) ||
			(BIO_write(bp,"\n",1) != 1))
			goto err;
		}

	buf = OPENSSL_malloc(PEM_BUFSIZE*8);
	if (buf == NULL)
		{
		reason=ERR_R_MALLOC_FAILURE;
		goto err;
		}

	i=j=0;
	while (len > 0)
		{
		n=(int)((len>(PEM_BUFSIZE*5))?(PEM_BUFSIZE*5):len);
		EVP_EncodeUpdate(&ctx,buf,&outl,&(data[j]),n);
		if ((outl) && (BIO_write(bp,(char *)buf,outl) != outl))
			goto err;
		i+=outl;
		len-=n;
		j+=n;
		}
	EVP_EncodeFinal(&ctx,buf,&outl);
	if ((outl > 0) && (BIO_write(bp,(char *)buf,outl) != outl)) goto err;
	OPENSSL_cleanse(buf, PEM_BUFSIZE*8);
	OPENSSL_free(buf);
	buf = NULL;
	if (	(BIO_write(bp,"-----END ",9) != 9) ||
		(BIO_write(bp,name,nlen) != nlen) ||
		(BIO_write(bp,"-----\n",6) != 6))
		goto err;
	return(i+outl);
err:
	if (buf) {
		OPENSSL_cleanse(buf, PEM_BUFSIZE*8);
		OPENSSL_free(buf);
	}
	OPENSSL_PUT_ERROR(PEM, PEM_write_bio, reason);
	return(0);
	}

#ifndef OPENSSL_NO_FP_API
int PEM_read(FILE *fp, char **name, char **header, unsigned char **data,
	     long *len)
        {
        BIO *b;
        int ret;

        if ((b=BIO_new(BIO_s_file())) == NULL)
		{
		OPENSSL_PUT_ERROR(PEM, PEM_read, ERR_R_BUF_LIB);
                return(0);
		}
        BIO_set_fp(b,fp,BIO_NOCLOSE);
        ret=PEM_read_bio(b, name, header, data,len);
        BIO_free(b);
        return(ret);
        }
#endif

int PEM_read_bio(BIO *bp, char **name, char **header, unsigned char **data,
	     long *len)
	{
	EVP_ENCODE_CTX ctx;
	int end=0,i,k,bl=0,hl=0,nohead=0;
	char buf[256];
	BUF_MEM *nameB;
	BUF_MEM *headerB;
	BUF_MEM *dataB,*tmpB;
	
	nameB=BUF_MEM_new();
	headerB=BUF_MEM_new();
	dataB=BUF_MEM_new();
	if ((nameB == NULL) || (headerB == NULL) || (dataB == NULL))
		{
		BUF_MEM_free(nameB);
		BUF_MEM_free(headerB);
		BUF_MEM_free(dataB);
		OPENSSL_PUT_ERROR(PEM, PEM_read_bio, ERR_R_MALLOC_FAILURE);
		return(0);
		}

	buf[254]='\0';
	for (;;)
		{
		i=BIO_gets(bp,buf,254);

		if (i <= 0)
			{
			OPENSSL_PUT_ERROR(PEM, PEM_read_bio, PEM_R_NO_START_LINE);
			goto err;
			}

		while ((i >= 0) && (buf[i] <= ' ')) i--;
		buf[++i]='\n'; buf[++i]='\0';

		if (strncmp(buf,"-----BEGIN ",11) == 0)
			{
			i=strlen(&(buf[11]));

			if (strncmp(&(buf[11+i-6]),"-----\n",6) != 0)
				continue;
			if (!BUF_MEM_grow(nameB,i+9))
				{
				OPENSSL_PUT_ERROR(PEM, PEM_read_bio, ERR_R_MALLOC_FAILURE);
				goto err;
				}
			memcpy(nameB->data,&(buf[11]),i-6);
			nameB->data[i-6]='\0';
			break;
			}
		}
	hl=0;
	if (!BUF_MEM_grow(headerB,256))
		{ OPENSSL_PUT_ERROR(PEM, PEM_read_bio, ERR_R_MALLOC_FAILURE); goto err; }
	headerB->data[0]='\0';
	for (;;)
		{
		i=BIO_gets(bp,buf,254);
		if (i <= 0) break;

		while ((i >= 0) && (buf[i] <= ' ')) i--;
		buf[++i]='\n'; buf[++i]='\0';

		if (buf[0] == '\n') break;
		if (!BUF_MEM_grow(headerB,hl+i+9))
			{ OPENSSL_PUT_ERROR(PEM, PEM_read_bio, ERR_R_MALLOC_FAILURE); goto err; }
		if (strncmp(buf,"-----END ",9) == 0)
			{
			nohead=1;
			break;
			}
		memcpy(&(headerB->data[hl]),buf,i);
		headerB->data[hl+i]='\0';
		hl+=i;
		}

	bl=0;
	if (!BUF_MEM_grow(dataB,1024))
		{ OPENSSL_PUT_ERROR(PEM, PEM_read_bio, ERR_R_MALLOC_FAILURE); goto err; }
	dataB->data[0]='\0';
	if (!nohead)
		{
		for (;;)
			{
			i=BIO_gets(bp,buf,254);
			if (i <= 0) break;

			while ((i >= 0) && (buf[i] <= ' ')) i--;
			buf[++i]='\n'; buf[++i]='\0';

			if (i != 65) end=1;
			if (strncmp(buf,"-----END ",9) == 0)
				break;
			if (i > 65) break;
			if (!BUF_MEM_grow_clean(dataB,i+bl+9))
				{
				OPENSSL_PUT_ERROR(PEM, PEM_read_bio, ERR_R_MALLOC_FAILURE);
				goto err;
				}
			memcpy(&(dataB->data[bl]),buf,i);
			dataB->data[bl+i]='\0';
			bl+=i;
			if (end)
				{
				buf[0]='\0';
				i=BIO_gets(bp,buf,254);
				if (i <= 0) break;

				while ((i >= 0) && (buf[i] <= ' ')) i--;
				buf[++i]='\n'; buf[++i]='\0';

				break;
				}
			}
		}
	else
		{
		tmpB=headerB;
		headerB=dataB;
		dataB=tmpB;
		bl=hl;
		}
	i=strlen(nameB->data);
	if (	(strncmp(buf,"-----END ",9) != 0) ||
		(strncmp(nameB->data,&(buf[9]),i) != 0) ||
		(strncmp(&(buf[9+i]),"-----\n",6) != 0))
		{
		OPENSSL_PUT_ERROR(PEM, PEM_read_bio, PEM_R_BAD_END_LINE);
		goto err;
		}

	EVP_DecodeInit(&ctx);
	i=EVP_DecodeUpdate(&ctx,
		(unsigned char *)dataB->data,&bl,
		(unsigned char *)dataB->data,bl);
	if (i < 0)
		{
		OPENSSL_PUT_ERROR(PEM, PEM_read_bio, PEM_R_BAD_BASE64_DECODE);
		goto err;
		}
	i=EVP_DecodeFinal(&ctx,(unsigned char *)&(dataB->data[bl]),&k);
	if (i < 0)
		{
		OPENSSL_PUT_ERROR(PEM, PEM_read_bio, PEM_R_BAD_BASE64_DECODE);
		goto err;
		}
	bl+=k;

	if (bl == 0) goto err;
	*name=nameB->data;
	*header=headerB->data;
	*data=(unsigned char *)dataB->data;
	*len=bl;
	OPENSSL_free(nameB);
	OPENSSL_free(headerB);
	OPENSSL_free(dataB);
	return(1);
err:
	BUF_MEM_free(nameB);
	BUF_MEM_free(headerB);
	BUF_MEM_free(dataB);
	return(0);
	}

/* Check pem string and return prefix length.
 * If for example the pem_str == "RSA PRIVATE KEY" and suffix = "PRIVATE KEY"
 * the return value is 3 for the string "RSA".
 */

int pem_check_suffix(const char *pem_str, const char *suffix)
	{
	int pem_len = strlen(pem_str);
	int suffix_len = strlen(suffix);
	const char *p;
	if (suffix_len + 1 >= pem_len)
		return 0;
	p = pem_str + pem_len - suffix_len;
	if (strcmp(p, suffix))
		return 0;
	p--;
	if (*p != ' ')
		return 0;
	return p - pem_str;
	}

int PEM_def_callback(char *buf, int size, int rwflag, void *userdata)
	{
	if (!buf || !userdata)
		{
		return 0;
		}
	size_t len = strlen((char *) userdata);
	if (len >= (size_t) size)
		{
		return 0;
		}
	strcpy(buf, (char *) userdata);
	return len;
	}
