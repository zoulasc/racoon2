/* $Id: crypto_openssl.c,v 1.68 2010/02/01 10:30:51 fukumoto Exp $ */
/*	$KAME: crypto_openssl.c,v 1.83 2003/11/13 19:51:43 sakane Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <config.h>

#include <assert.h>
#include <sys/types.h>
#include <sys/param.h>
#if TIME_WITH_SYS_TIME
#  include <sys/time.h>
#  include <time.h>
#else
#  if HAVE_SYS_TIME_H
#    include <sys/time.h>
#  else
#    include <time.h>
#  endif
#endif

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <netinet/in.h>		/* for htonl() */

#include "racoon.h"

#include "var.h"
#include "crypto_impl.h"
#include "debug.h"
#include "gcmalloc.h"

#include <openssl/err.h>
#ifdef WITH_OPENSSL_ENGINE
#include <openssl/engine.h>
#endif

/*
 * I hate to cast every parameter to des_xx into void *, but it is
 * necessary for SSLeay/OpenSSL portability.  It sucks.
 */

#ifdef HAVE_SIGNING_C
static int cb_check_cert (int, X509_STORE_CTX *);
static X509 *mem2x509 (rc_vchar_t *);
#endif

static caddr_t eay_hmac_init(rc_vchar_t *, const EVP_MD *);

void
eay_init(void)
{
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
#ifdef WITH_OPENSSL_ENGINE
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();
#endif
}

void
eay_cleanup(void)
{
#ifdef WITH_OPENSSL_ENGINE
	ENGINE_cleanup();
#endif
}

#ifdef HAVE_SIGNING_C

/*
 * internal to vmbuf conversion
 */
#define	IMPLEMENT_I2V(type_)	IMPLEMENT_I2V_name(type_, type_)

#define	IMPLEMENT_I2V_name(type_, name_)				\
	rc_vchar_t * i2v_##name_(v)					\
	     type_ * v;							\
	{								\
		rc_vchar_t	* buf;					\
		int	len;						\
		unsigned char	* bp;					\
									\
		len = i2d_##name_(v, NULL);				\
		if (len == 0) return 0;					\
		buf = rc_vmalloc(len);					\
		if (! buf) return 0;					\
		bp = (unsigned char *) buf->v;				\
		len = i2d_##name_(v, &bp);				\
		if (len == 0) {						\
			rc_vfree(buf);					\
			return 0;					\
		}							\
		return buf;						\
	}

IMPLEMENT_I2V(X509)
IMPLEMENT_I2V(X509_NAME)
IMPLEMENT_I2V_name(EVP_PKEY, PUBKEY)
IMPLEMENT_I2V_name(EVP_PKEY, PublicKey)
IMPLEMENT_I2V_name(EVP_PKEY, PrivateKey)
IMPLEMENT_I2V(PKCS12)


/* X509 Certificate */
/*
 * convert the string of the subject name into DER
 * e.g. str = "C=JP, ST=Kanagawa";
 */
rc_vchar_t *
eay_str2asn1dn(char *str, int len)
{
	X509_NAME *name;
	char *buf;
	char *field, *value;
	int i, j;
	rc_vchar_t *ret;

	buf = racoon_malloc(len + 1);
	if (!buf) {
#ifdef EAYDEBUG
		printf("failed to allocate buffer\n");
#endif
		return NULL;
	}
	memcpy(buf, str, len);

	name = X509_NAME_new();

	field = &buf[0];
	value = NULL;
	for (i = 0; i < len; i++) {
		if (!value && buf[i] == '=') {
			buf[i] = '\0';
			value = &buf[i + 1];
			continue;
		} else if (buf[i] == ',' || buf[i] == '/') {
			buf[i] = '\0';
#if 0
			printf("[%s][%s]\n", field, value);
#endif
			if (!X509_NAME_add_entry_by_txt(name, field,
			    MBSTRING_ASC, (unsigned char *)value, -1, -1, 0))
				goto err;
			for (j = i + 1; j < len; j++) {
				if (buf[j] != ' ')
					break;
			}
			field = &buf[j];
			value = NULL;
			continue;
		}
	}
	buf[len] = '\0';
#if 0
	printf("[%s][%s]\n", field, value);
#endif
	if (!X509_NAME_add_entry_by_txt(name, field,
	    MBSTRING_ASC, (unsigned char *)value, -1, -1, 0))
		goto err;

	ret = i2v_X509_NAME(name);
	X509_NAME_free(name);
	return ret;

      err:
	if (buf)
		racoon_free(buf);
	if (name)
		X509_NAME_free(name);
	return NULL;
}

/*
 * compare two subjectNames.
 * OUT:        0: equal
 *	positive:
 *	      -1: other error.
 */
int
eay_cmp_asn1dn(rc_vchar_t *n1, rc_vchar_t *n2)
{
	X509_NAME *a = NULL, *b = NULL;
	BPP_const unsigned char *p;
	int i = -1;

	p = (unsigned char *)n1->v;
	if (!d2i_X509_NAME(&a, &p, n1->l))
		goto end;
	p = (unsigned char *)n2->v;
	if (!d2i_X509_NAME(&b, &p, n2->l))
		goto end;

	i = X509_NAME_cmp(a, b);

      end:
	if (a)
		X509_NAME_free(a);
	if (b)
		X509_NAME_free(b);
	return i;
}

/*
 * this functions is derived from apps/verify.c in OpenSSL0.9.5
 */
int
eay_check_x509cert(rc_vchar_t *cert, char *CApath)
{
	X509_STORE *cert_ctx = NULL;
	X509_LOOKUP *lookup = NULL;
	X509 *x509 = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x00905100L
	X509_STORE_CTX *csc;
#else
	X509_STORE_CTX csc;
#endif
	int error = -1;

	cert_ctx = X509_STORE_new();
	if (cert_ctx == NULL)
		goto end;
	X509_STORE_set_verify_cb_func(cert_ctx, cb_check_cert);

	if (!CApath)
		error = X509_STORE_set_default_paths(cert_ctx);
	else {
		X509_STORE_load_locations(cert_ctx, NULL, CApath);

		lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());
		if (lookup == NULL)
			goto end;
		X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);	/* XXX */

		lookup = X509_STORE_add_lookup(cert_ctx,
					       X509_LOOKUP_hash_dir());
		if (lookup == NULL)
			goto end;
		error = X509_LOOKUP_add_dir(lookup, CApath, X509_FILETYPE_PEM);
	}
	if (!error) {
		error = -1;
		goto end;
	}
	error = -1;		/* initialized */

	/* read the certificate to be verified */
	x509 = mem2x509(cert);
	if (x509 == NULL)
		goto end;

#if OPENSSL_VERSION_NUMBER >= 0x00905100L
	csc = X509_STORE_CTX_new();
	if (csc == NULL)
		goto end;
	X509_STORE_CTX_init(csc, cert_ctx, x509, NULL);
	error = X509_verify_cert(csc);
	X509_STORE_CTX_cleanup(csc);
#else
	X509_STORE_CTX_init(&csc, cert_ctx, x509, NULL);
	error = X509_verify_cert(&csc);
	X509_STORE_CTX_cleanup(&csc);
#endif

	/*
	 * if x509_verify_cert() is successful then the value of error is
	 * set non-zero.
	 */
	error = error ? 0 : -1;

      end:
	if (error) {
#ifdef EAYDEBUG
		printf("%s\n", eay_strerror());
#else
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "%s\n", eay_strerror());
#endif
	}
	if (cert_ctx != NULL)
		X509_STORE_free(cert_ctx);
	if (x509 != NULL)
		X509_free(x509);

	return (error);
}

/*
 * callback function for verifing certificate.
 * this function is derived from cb() in openssl/apps/s_server.c
 */
static int
cb_check_cert(int ok, X509_STORE_CTX *ctx)
{
	char buf[256];
	int log_tag;

	if (!ok) {
		X509_NAME_oneline(X509_get_subject_name(ctx->current_cert),
				  buf, 256);
		/*
		 * since we are just checking the certificates, it is
		 * ok if they are self signed. But we should still warn
		 * the user.
		 */
		switch (ctx->error) {
		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
#if OPENSSL_VERSION_NUMBER >= 0x00905100L
		case X509_V_ERR_INVALID_CA:
		case X509_V_ERR_PATH_LENGTH_EXCEEDED:
		case X509_V_ERR_INVALID_PURPOSE:
#endif
			ok = 1;
			log_tag = PLOG_PROTOWARN;
			break;
		case X509_V_ERR_CERT_HAS_EXPIRED:
		default:
			log_tag = PLOG_PROTOERR;
		}
#ifndef EAYDEBUG
		plog(log_tag, PLOGLOC, NULL,
		     "%s(%d) at depth:%d SubjectName:%s\n",
		     X509_verify_cert_error_string(ctx->error),
		     ctx->error, ctx->error_depth, buf);
#else
		printf("%d: %s(%d) at depth:%d SubjectName:%s\n",
		       log_tag,
		       X509_verify_cert_error_string(ctx->error),
		       ctx->error, ctx->error_depth, buf);
#endif
	}
	ERR_clear_error();

	return ok;
}

/*
 * convert ASN1_TIME to timeval
 * XXX time_t may not be adequate
 */
#ifndef HAVE_TIMEGM
time_t
timegm(struct tm * tm)
{
	char *tz;
	time_t value;

	tz = getenv("TZ");
	putenv("TZ=");
	tzset();
	value = mktime(tm);
	if (tz)
		setenv("TZ", tz, 1);
	else
		unsetenv("TZ");
	tzset();
	return value;
}
#endif

static int
c2(unsigned char *s)
{
	return (s[0] - '0') * 10 + (s[1] - '0');
}

static int
eay_utctime(struct timeval *t, ASN1_TIME *u)
{
	int len;
	unsigned char *s;
	int i;
	struct tm tm;

	if (u->type != V_ASN1_UTCTIME)
		return -1;
	len = u->length;
	s = (unsigned char *)u->data;

	/*
	 * YYMMDDhhmmssZ
	 */
	/*
	 * Restriction by DER
	 * + encoding shall terminate with "Z"
	 * + seconds element shall always be present
	 */
	/* (RFC3280)
	 * 4.1.2.5.1  UTCTime
	 * 
	 * The universal time type, UTCTime, is a standard ASN.1 type intended
	 * for representation of dates and time.  UTCTime specifies the year
	 * through the two low order digits and time is specified to the
	 * precision of one minute or one second.  UTCTime includes either Z
	 * (for Zulu, or Greenwich Mean Time) or a time differential.
	 * 
	 * For the purposes of this profile, UTCTime values MUST be expressed
	 * Greenwich Mean Time (Zulu) and MUST include seconds (i.e., times are
	 * YYMMDDHHMMSSZ), even where the number of seconds is zero.  Conforming
	 * systems MUST interpret the year field (YY) as follows:
	 * 
	 * Where YY is greater than or equal to 50, the year SHALL be
	 * interpreted as 19YY; and
	 * 
	 * Where YY is less than 50, the year SHALL be interpreted as 20YY.
	 */

	if (len != 13)
		return -1;
	for (i = 0; i < 12; ++i)
		if (!isdigit(s[i]))
			return -1;
	if (s[12] != 'Z')
		return -1;

	tm.tm_year = c2(&s[0]);
	if (tm.tm_year < 50)
		tm.tm_year += 100;

	tm.tm_mon = c2(&s[2]) - 1;	/* 0..11 */
	tm.tm_mday = c2(&s[4]);
	tm.tm_hour = c2(&s[6]);
	tm.tm_min = c2(&s[8]);
	tm.tm_sec = c2(&s[10]);

	t->tv_sec = timegm(&tm);
	t->tv_usec = 0;
	return 0;
}

static int
eay_generalizedtime(struct timeval *t, ASN1_TIME *g)
{
	int len;
	unsigned char *s;
	int i;
	struct tm tm;

	if (g->type != V_ASN1_GENERALIZEDTIME)
		return -1;
	len = g->length;
	s = (unsigned char *)g->data;

	/*
	 * (a) implicit localtime
	 * "20050401235959.9"   year4+month2+day2+time(with comma or period)
	 *
	 * (b) UTC
	 * "20050401235959.9Z"  (a)+"Z"
	 *
	 * (c) explicit localtime
	 * "20050401235959.9+0900"      (a)+timezone difference
	 */
	/*
	 * Restriction by DER
	 * - encoding shall terminate with a "Z"
	 * - seconds element shall always be present
	 * - fractional-seconds elements, if present, shall omit all trailing zeros;
	 * - decimal point element, if present, shall be the point option ","
	 * (XXX this doesn't match with OpenSSL)
	 */
	/* (RFC3280)
	 * 4.1.2.5.2  GeneralizedTime
	 * 
	 * The generalized time type, GeneralizedTime, is a standard ASN.1 type
	 * for variable precision representation of time.  Optionally, the
	 * GeneralizedTime field can include a representation of the time
	 * differential between local and Greenwich Mean Time.
	 * 
	 * For the purposes of this profile, GeneralizedTime values MUST be
	 * expressed Greenwich Mean Time (Zulu) and MUST include seconds (i.e.,
	 * times are YYYYMMDDHHMMSSZ), even where the number of seconds is zero.
	 * GeneralizedTime values MUST NOT include fractional seconds.
	 */

	if (len != 15)
		return -1;
	for (i = 0; i < 14; ++i)
		if (!isdigit(s[i]))
			return -1;
	if (s[14] != 'Z')
		return -1;

	tm.tm_year = (c2(&s[0]) * 100 + c2(&s[2])) - 1900;
	tm.tm_mon = c2(&s[4]) - 1;
	tm.tm_mday = c2(&s[6]);
	tm.tm_hour = c2(&s[8]);
	tm.tm_min = c2(&s[10]);
	tm.tm_sec = c2(&s[12]);

	t->tv_sec = timegm(&tm);
	t->tv_usec = 0;
	return 0;
}

static int
eay_time(struct timeval *t, ASN1_TIME *s)
{
	if (!s)
		return -1;

	switch (s->type) {
	case V_ASN1_UTCTIME:
		return eay_utctime(t, s);
		break;
	case V_ASN1_GENERALIZEDTIME:
		return eay_generalizedtime(t, s);
	default:
		return -1;
	}
}

/*
 * extract pubkey (asn1) from x509 cert (asn1)
 */
rc_vchar_t *
eay_get_x509_pubkey(rc_vchar_t *cert, struct timeval *due_time)
{
	EVP_PKEY *evp = NULL;
	rc_vchar_t *pkey = NULL;
	X509 *x509 = NULL;

	x509 = mem2x509(cert);
	if (x509 == NULL)
		return NULL;

	/* Get public key - eay */
	evp = X509_get_pubkey(x509);
	if (evp == NULL)
		return NULL;

	pkey = i2v_PUBKEY(evp);
	if (due_time) {
		if (eay_time(due_time, X509_get_notAfter(x509)) != 0) {
			EVP_PKEY_free(evp);
			return NULL;
		}

		/* *due_time = ASN1_UTCTIME_get(X509_get_notAfter(pkey)); */
	}
	EVP_PKEY_free(evp);
	return pkey;
}

/*
 * get a subjectName from X509 certificate.
 */
rc_vchar_t *
eay_get_x509asn1subjectname(rc_vchar_t *cert)
{
	X509 *x509 = NULL;
	rc_vchar_t *name = NULL;
	int error = -1;

	x509 = mem2x509(cert);
	if (x509 == NULL)
		goto end;

	name = i2v_X509_NAME(X509_get_subject_name(x509));
	error = 0;
      end:
	if (error) {
#ifndef EAYDEBUG
		plog(PLOG_PROTOERR, PLOGLOC, NULL, "%s\n", eay_strerror());
#else
		printf("%s\n", eay_strerror());
#endif
		if (name) {
			rc_vfree(name);
			name = NULL;
		}
	}
	if (x509)
		X509_free(x509);

	return name;
}

/*
 * get the subjectAltName from X509 certificate.
 * the name must be terminated by '\0'.
 */
int
eay_get_x509subjectaltname(rc_vchar_t *cert, char **altname, int *type, int pos)
{
	X509 *x509 = NULL;
	GENERAL_NAMES *gens;
	GENERAL_NAME *gen;
	int i, len;
	int error = -1;

	*altname = NULL;
	*type = GENT_OTHERNAME;

	x509 = mem2x509(cert);
	if (x509 == NULL)
		goto end;

	gens = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
	if (gens == NULL)
		goto end;

	for (i = 0; i < sk_GENERAL_NAME_num(gens); i++) {
		if (i + 1 != pos)
			continue;
		break;
	}

	/* there is no data at "pos" */
	if (i == sk_GENERAL_NAME_num(gens))
		goto end;

	gen = sk_GENERAL_NAME_value(gens, i);

	/* make sure if the data is terminated by '\0'. */
	if (gen->d.ia5->data[gen->d.ia5->length] != '\0') {
#ifndef EAYDEBUG
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "data is not terminated by '\\0'.\n");
		plogdump(PLOG_PROTOERR, PLOGLOC, 0,
			 gen->d.ia5->data, gen->d.ia5->length + 1);
#else
		hexdump(gen->d.ia5->data, gen->d.ia5->length + 1);
#endif
		goto end;
	}

	len = gen->d.ia5->length + 1;
	*altname = racoon_malloc(len);
	if (!*altname)
		goto end;

	strlcpy(*altname, (char *)gen->d.ia5->data, len);
	*type = gen->type;

	error = 0;

      end:
	if (error) {
		if (*altname) {
			racoon_free(*altname);
			*altname = NULL;
		}
#ifndef EAYDEBUG
		plog(PLOG_PROTOERR, PLOGLOC, NULL, "%s\n", eay_strerror());
#else
		printf("%s\n", eay_strerror());
#endif
	}
	if (x509)
		X509_free(x509);

	return error;
}

/*
 * decode a X509 certificate and make a readable text terminated '\n'.
 * return the buffer allocated, so must free it later.
 */
char *
eay_get_x509text(rc_vchar_t *cert)
{
	X509 *x509 = NULL;
	BIO *bio = NULL;
	char *text = NULL;
	unsigned char *bp = NULL;
	int len = 0;
	int error = -1;

	x509 = mem2x509(cert);
	if (x509 == NULL)
		goto end;

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		goto end;

	error = X509_print(bio, x509);
	if (error != 1) {
		error = -1;
		goto end;
	}

	len = BIO_get_mem_data(bio, &bp);
	text = racoon_malloc(len + 1);
	if (text == NULL)
		goto end;
	memcpy(text, bp, len);
	text[len] = '\0';

	error = 0;

      end:
	if (error) {
		if (text) {
			racoon_free(text);
			text = NULL;
		}
#ifndef EAYDEBUG
		plog(PLOG_PROTOERR, PLOGLOC, NULL, "%s\n", eay_strerror());
#else
		printf("%s\n", eay_strerror());
#endif
	}
	if (bio)
		BIO_free(bio);
	if (x509)
		X509_free(x509);

	return text;
}

/* get X509 structure from buffer. */
static X509 *
mem2x509(rc_vchar_t *cert)
{
	X509 *x509;

#ifndef EAYDEBUG
	{
		BPP_const unsigned char *bp;

		bp = (unsigned char *)cert->v;
		x509 = d2i_X509(NULL, &bp, cert->l);
	}
#else
	{
		BIO *bio;
		int len;

		bio = BIO_new(BIO_s_mem());
		if (bio == NULL)
			return NULL;
		len = BIO_write(bio, cert->v, cert->l);
		if (len == -1)
			return NULL;
		x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		BIO_free(bio);
	}
#endif
	return x509;
}

/*
 * get a X509 certificate from local file.
 * a certificate must be PEM format.
 * Input:
 *	path to a certificate.
 * Output:
 *	NULL if error occured
 *	other is the cert.
 */
rc_vchar_t *
eay_get_x509cert(const char *path)
{
	FILE *fp;
	X509 *x509;
	rc_vchar_t *cert;

	/* Read private key */
	fp = fopen(path, "r");
	if (fp == NULL)
		return NULL;
#if OPENSSL_VERSION_NUMBER >= 0x00904100L
	x509 = PEM_read_X509(fp, NULL, NULL, NULL);
#else
	x509 = PEM_read_X509(fp, NULL, NULL);
#endif
	fclose(fp);

	if (x509 == NULL)
		return NULL;

	cert = i2v_X509(x509);
	X509_free(x509);
	return cert;
}

/*
 * sign a souce by X509 signature.
 * XXX: to be get hash type from my cert ?
 *	to be handled EVP_dss().
 */
/*ARGSUSED*/
rc_vchar_t *
eay_get_x509sign(rc_vchar_t *source, rc_vchar_t *privkey, rc_vchar_t *cert)
{
	rc_vchar_t *sig = NULL;

	sig = eay_rsa_sign(source, privkey);

	return sig;
}

/*
 * check a X509 signature
 *	XXX: to be get hash type from my cert ?
 *		to be handled EVP_dss().
 * OUT: return -1 when error.
 *	0
 */
int
eay_check_x509sign(rc_vchar_t *source, rc_vchar_t *sig, rc_vchar_t *cert)
{
	int retval;
	rc_vchar_t *pubkey;

	pubkey = eay_get_x509_pubkey(cert, 0);
	if (! pubkey)
		return -1;
	retval = eay_rsa_verify(source, sig, pubkey);
	rc_vfree(pubkey);
	return retval;
}

/*
 * get PKCS#1 Private Key of PEM format from local file.
 */
rc_vchar_t *
eay_get_pkcs1privkey(const char *path)
{
	FILE *fp;
	EVP_PKEY *evp = NULL;
	rc_vchar_t *pkey = NULL;

	/* Read private key */
	fp = fopen(path, "r");
	if (fp == NULL)
		return NULL;

#if OPENSSL_VERSION_NUMBER >= 0x00904100L
	evp = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
#else
	evp = PEM_read_PrivateKey(fp, NULL, NULL);
#endif
	fclose(fp);

	if (evp == NULL)
		return NULL;

	pkey = i2v_PrivateKey(evp);
	EVP_PKEY_free(evp);
	return pkey;
}

/*
 * get PKCS#1 Public Key of PEM format from local file.
 */
rc_vchar_t *
eay_get_pkcs1pubkey(const char *path)
{
	FILE *fp;
	EVP_PKEY *evp = NULL;
	rc_vchar_t *pkey = NULL;
	X509 *x509 = NULL;

	/* Read private key */
	fp = fopen(path, "r");
	if (fp == NULL)
		return NULL;

#if OPENSSL_VERSION_NUMBER >= 0x00904100L
	x509 = PEM_read_X509(fp, NULL, NULL, NULL);
#else
	x509 = PEM_read_X509(fp, NULL, NULL);
#endif
	fclose(fp);

	if (x509 == NULL)
		return NULL;

	/* Get public key - eay */
	evp = X509_get_pubkey(x509);
	if (evp == NULL)
		return NULL;

	pkey = i2v_PublicKey(evp);
	EVP_PKEY_free(evp);
	return pkey;
}

/*
 * read PKCS12 file (check syntax), then return vmbuf
 */
rc_vchar_t *
eay_get_pkcs12(const char *path)
{
	FILE *fp = 0;
	PKCS12 *p12 = 0;
	rc_vchar_t *buf = 0;

	fp = fopen(path, "r");
	if (fp == NULL)
		goto end;

	p12 = d2i_PKCS12_fp(fp, NULL);
	if (!p12)
		goto end;

	buf = i2v_PKCS12(p12);
      end:
	if (fp)
		fclose(fp);
	if (p12)
		PKCS12_free(p12);
	return buf;
}

/*
 * extract x509cert from PKCS12 (in vmbuf)
 */
rc_vchar_t *
eay_get_pkcs12_x509cert(rc_vchar_t *pk12, const char *passphrase)
{
	BPP_const unsigned char *bp;
	int success;
	PKCS12 *p12;
	X509 *x509;
	rc_vchar_t *cert = 0;

	bp = (unsigned char *)pk12->v;
	p12 = d2i_PKCS12(NULL, &bp, pk12->l);
	success = PKCS12_parse(p12, passphrase, NULL, &x509, NULL);
	PKCS12_free(p12);
	if (!success)
		return 0;
	cert = i2v_X509(x509);
	X509_free(x509);
	return cert;
}

/*
 * extract private key from PKCS12 (in vmbuf)
 */
rc_vchar_t *
eay_get_pkcs12_privkey(rc_vchar_t *pk12, const char *passphrase)
{
	BPP_const unsigned char *bp;
	int success;
	PKCS12 *p12;
	EVP_PKEY *privkey;
	rc_vchar_t *buf = 0;

	bp = (unsigned char *)pk12->v;
	p12 = d2i_PKCS12(NULL, &bp, pk12->l);
	success = PKCS12_parse(p12, passphrase, &privkey, NULL, NULL);
	PKCS12_free(p12);
	if (!success)
		return 0;

	buf = i2v_PrivateKey(privkey);
	EVP_PKEY_free(privkey);
	return buf;
}
#endif

rc_vchar_t *
eay_rsa_sign(rc_vchar_t *src, rc_vchar_t *privkey)
{
	EVP_PKEY *evp;
	BPP_const unsigned char *bp;
	rc_vchar_t *sig = NULL;
	int len;
	int pad = RSA_PKCS1_PADDING;

	bp = (unsigned char *)privkey->v;
	/* XXX to be handled EVP_PKEY_DSA */
	evp = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &bp, privkey->l);
	if (evp == NULL)
		return NULL;

	/* XXX: to be handled EVP_dss() */
	/* XXX: Where can I get such parameters ?  From my cert ? */

	len = RSA_size(evp->pkey.rsa);

	sig = rc_vmalloc(len);
	if (sig == NULL)
		return NULL;

	len = RSA_private_encrypt(src->l, (unsigned char *)src->v,
				  (unsigned char *)sig->v, evp->pkey.rsa, pad);
	EVP_PKEY_free(evp);
	if (len == 0 || (size_t)len != sig->l) {
		rc_vfree(sig);
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "%s\n", eay_strerror());
		sig = NULL;
	}

	return sig;
}

int
eay_rsa_verify(rc_vchar_t *src, rc_vchar_t *sig, rc_vchar_t *pubkey)
{
	EVP_PKEY *evp;
	BPP_const unsigned char *bp;
	rc_vchar_t *xbuf = NULL;
	int pad = RSA_PKCS1_PADDING;
	int len = 0;
	int error;

	bp = (unsigned char *)pubkey->v;
	evp = d2i_PUBKEY(NULL, &bp, pubkey->l);
	if (evp == NULL) {
#ifndef EAYDEBUG
		plog(PLOG_INTERR, PLOGLOC, NULL, "%s\n", eay_strerror());
#endif
		return -1;
	}

	len = RSA_size(evp->pkey.rsa);

	xbuf = rc_vmalloc(len);
	if (xbuf == NULL) {
#ifndef EAYDEBUG
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "failed allocating memory\n");
#endif
		EVP_PKEY_free(evp);
		return -1;
	}

	len = RSA_public_decrypt(sig->l, (unsigned char *)sig->v,
				 (unsigned char *)xbuf->v, evp->pkey.rsa, pad);
#ifndef EAYDEBUG
	if (len == 0 || (size_t)len != src->l)
		plog(PLOG_PROTOERR, PLOGLOC, NULL, "%s\n", eay_strerror());
#endif
	EVP_PKEY_free(evp);
	if (len == 0 || (size_t)len != src->l) {
		rc_vfree(xbuf);
		return -1;
	}

	error = memcmp(src->v, xbuf->v, src->l);
	rc_vfree(xbuf);
	if (error != 0)
		return -1;

	return 0;
}

/* (RFC2437) */
/*
 * calculate RSA_sign(Hash(octets), privkey) and return vmbuf
 *
 * hash_type:  name string of Hash
 * octets:     message to sign
 * privkey:    vmbuf of private key in PKCS#1 format
 */
rc_vchar_t *
eay_rsassa_pkcs1_v1_5_sign(const char *hash_type, rc_vchar_t *octets, rc_vchar_t *privkey)
{
	EVP_PKEY *pkey;
	BPP_const unsigned char *bp;
	int len;
	rc_vchar_t *sig = 0;
	unsigned int siglen;
	const EVP_MD *md;
	EVP_MD_CTX ctx;

	bp = (unsigned char *)privkey->v;
	/* convert private key from vmbuf to internal data */
	pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &bp, privkey->l);
	if (pkey == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed obtaining private key: %s\n", eay_strerror());
		goto fail;
	}

	len = RSA_size(pkey->pkey.rsa);
	sig = rc_vmalloc(len);
	if (sig == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "failed allocating memory\n");
		goto fail;
	}

	/* RSA sign with private key */
	md = EVP_get_digestbyname(hash_type);
	if (!md) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to find digest algorithm %s\n", hash_type);
		goto fail;
	}
	EVP_MD_CTX_init(&ctx);
	EVP_SignInit(&ctx, md);
	EVP_SignUpdate(&ctx, octets->v, octets->l);
	if (EVP_SignFinal(&ctx, (unsigned char *)sig->v, &siglen, pkey) <= 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "RSA_sign failed: %s\n", eay_strerror());
		EVP_MD_CTX_cleanup(&ctx);
		goto fail;
	}
	EVP_MD_CTX_cleanup(&ctx);
	if (sig->l != siglen) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "unexpected signature length %d\n", siglen);
		goto fail;
	}
	EVP_PKEY_free(pkey);
	return sig;

      fail:
	if (sig)
		rc_vfree(sig);
	if (pkey)
		EVP_PKEY_free(pkey);
	return 0;
}

/*
 * hash_type:	name string of Hash function
 * octets:	message octets
 * sig: 	received signature data
 * pubkey:	vmbuf of public key in PKCS#1 format
 *
 * returns 0 if successful, non-0 otherwise
 */
int
eay_rsassa_pkcs1_v1_5_verify(const char *hash_type, rc_vchar_t *octets, rc_vchar_t *sig, rc_vchar_t *pubkey)
{
	EVP_PKEY *pkey;
	BPP_const unsigned char *bp;
	const EVP_MD *md;
	EVP_MD_CTX ctx;

	bp = (unsigned char *)pubkey->v;
	pkey = d2i_PUBKEY(NULL, &bp, pubkey->l);
	if (pkey == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed obtaining public key: %s\n", eay_strerror());
		goto fail;
	}
	if (pkey->type != EVP_PKEY_RSA) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "public key is not for RSA\n");
		goto fail;
	}

	md = EVP_get_digestbyname(hash_type);
	if (!md) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to find the algorithm engine for %s\n", hash_type);
		goto fail;
	}
	EVP_MD_CTX_init(&ctx);
	EVP_VerifyInit(&ctx, md);
	EVP_VerifyUpdate(&ctx, octets->v, octets->l);
	if (EVP_VerifyFinal(&ctx, (unsigned char *)sig->v, sig->l, pkey) <= 0) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "RSA_verify failed: %s\n", eay_strerror());
		EVP_MD_CTX_cleanup(&ctx);
		goto fail;
	}
	EVP_MD_CTX_cleanup(&ctx);

	EVP_PKEY_free(pkey);
	return 0;

      fail:
	if (pkey)
		EVP_PKEY_free(pkey);
	return -1;
}

/*
 * generates a DSS signature over SHA1 hash of octets
 */
rc_vchar_t *
eay_dss_sign(rc_vchar_t *octets, rc_vchar_t *privkey)
{
	EVP_PKEY *pkey;
	BPP_const unsigned char *bp;
	const EVP_MD *md;
	EVP_MD_CTX ctx;
	int len;
	rc_vchar_t *sig = 0;
	unsigned int siglen;

	bp = (unsigned char *)privkey->v;
	pkey = d2i_PrivateKey(EVP_PKEY_DSA3, NULL, &bp, privkey->l);
	if (pkey == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed obtaining private key: %s\n", eay_strerror());
		goto fail;
	}

	len = DSA_size(pkey->pkey.dsa);
	sig = rc_vmalloc(len);
	if (sig == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL, "failed allocating memory\n");
		goto fail;
	}

	md = EVP_dss1();
	EVP_MD_CTX_init(&ctx);
	EVP_SignInit(&ctx, md);
	EVP_SignUpdate(&ctx, octets->v, octets->l);
	if (EVP_SignFinal(&ctx, (unsigned char *)sig->v, &siglen, pkey) <= 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "DSS sign failed: %s\n", eay_strerror());
		EVP_MD_CTX_cleanup(&ctx);
		goto fail;
	}
	EVP_MD_CTX_cleanup(&ctx);

	if (siglen > sig->l) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "unexpected signature length (%u > %lu)\n",
		     siglen, (unsigned long)sig->l);
		goto fail;
	}
	if (siglen < sig->l)
		sig = rc_vrealloc(sig, siglen);
	EVP_PKEY_free(pkey);
	return sig;

      fail:
	if (sig)
		rc_vfree(sig);
	if (pkey)
		EVP_PKEY_free(pkey);
	return 0;
}

/*
 * verifies DSS signature
 * returns 0 if successfully verified, non-0 otherwise
 */
int
eay_dss_verify(rc_vchar_t *octets, rc_vchar_t *sig, rc_vchar_t *pubkey)
{
	EVP_PKEY *pkey;
	BPP_const unsigned char *bp;
	const EVP_MD *md;
	EVP_MD_CTX ctx;

	bp = (unsigned char *)pubkey->v;
	pkey = d2i_PUBKEY(NULL, &bp, pubkey->l);
	if (pkey == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed obtaining public key: %s\n", eay_strerror());
		goto fail;
	}
	if (pkey->type != EVP_PKEY_DSA) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "public key is not for DSS\n");
		goto fail;
	}

	md = EVP_dss1();
	EVP_MD_CTX_init(&ctx);
	EVP_VerifyInit(&ctx, md);
	EVP_VerifyUpdate(&ctx, octets->v, octets->l);
	if (EVP_VerifyFinal(&ctx, (unsigned char *)sig->v, sig->l, pkey) <= 0) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "DSS verify failed: %s\n", eay_strerror());
		EVP_MD_CTX_cleanup(&ctx);
		goto fail;
	}
	EVP_MD_CTX_cleanup(&ctx);

	EVP_PKEY_free(pkey);
	return 0;

      fail:
	if (pkey)
		EVP_PKEY_free(pkey);
	return -1;
}

/*
 * get error string
 * MUST load ERR_load_crypto_strings() first.
 * XXX returns local static buffer
 */
char *
eay_strerror(void)
{
	static char ebuf[512];
	int len = 0, n;
	unsigned long l;
	char buf[200];
#if OPENSSL_VERSION_NUMBER >= 0x00904100L
	const char *file, *data;
#else
	char *file, *data;
#endif
	int line, flags;
	unsigned long es;

	es = CRYPTO_thread_id();

	while ((l = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
		n = snprintf(ebuf + len, sizeof(ebuf) - len,
			     "%lu:%s:%s:%d:%s ",
			     es, ERR_error_string(l, buf), file, line,
			     (flags & ERR_TXT_STRING) ? data : "");
		if (n < 0 || (size_t)n >= sizeof(ebuf) - len)
			break;
		len += n;
		if (sizeof(ebuf) < (size_t)len)
			break;
	}

	return ebuf;
}

/*
 * encrypt/decrypt with EVP interface
 */
static rc_vchar_t *
evp_encrypt(const EVP_CIPHER *ciph, rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	EVP_CIPHER_CTX ctx;
	int outl;

	if (!iv || iv->l < (size_t)EVP_CIPHER_block_size(ciph))
		return NULL;

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	EVP_CIPHER_CTX_init(&ctx);
	if (!EVP_EncryptInit(&ctx, ciph, (unsigned char *)key->v, (unsigned char *)iv->v))
		goto fail;
	if (!EVP_CIPHER_CTX_set_padding(&ctx, 0))
		goto fail;
	if (!EVP_EncryptUpdate(&ctx, (unsigned char *)res->v, &outl, (unsigned char *)data->v,
	     data->l))
		goto fail;
	if ((size_t)outl != data->l) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "encrypt output length does not match (%d != %lu)\n",
		     outl, (unsigned long)data->l);
		goto fail;
	}
	if (!EVP_EncryptFinal(&ctx, NULL, &outl))
		goto fail;

	EVP_CIPHER_CTX_cleanup(&ctx);
	return res;

      fail:
	if (res)
		rc_vfree(res);
	EVP_CIPHER_CTX_cleanup(&ctx);
	return NULL;
}

static rc_vchar_t *
evp_decrypt(const EVP_CIPHER *ciph, rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	EVP_CIPHER_CTX ctx;
	int outl;

	if (!iv || iv->l < (size_t)EVP_CIPHER_block_size(ciph))
		return NULL;

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	EVP_CIPHER_CTX_init(&ctx);
	if (!EVP_DecryptInit(&ctx, ciph, (unsigned char *)key->v, (unsigned char *)iv->v))
		goto fail;
	if (!EVP_CIPHER_CTX_set_padding(&ctx, 0))
		goto fail;
	if (!EVP_DecryptUpdate(&ctx, (unsigned char *)res->v, &outl, (unsigned char *)data->v,
	     data->l))
		goto fail;
	if ((size_t)outl != data->l) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "decrypt output length does not match (%d != %lu)\n",
		     outl, (unsigned long)data->l);
		goto fail;
	}
	if (!EVP_DecryptFinal(&ctx, NULL, &outl))
		goto fail;
	EVP_CIPHER_CTX_cleanup(&ctx);
	return res;

      fail:
	if (res)
		rc_vfree(res);
	EVP_CIPHER_CTX_cleanup(&ctx);
	return NULL;
}

/*
 * DES-CBC
 */
rc_vchar_t *
eay_des_encrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
#ifdef USE_NEW_DES_API
	DES_key_schedule ks;
#else
	des_key_schedule ks;
#endif

	if (data->l % 8)
		return NULL;

#ifdef USE_NEW_DES_API
	if (DES_key_sched((void *)key->v, &ks) != 0)
#else
	if (des_key_sched((void *)key->v, ks) != 0)
#endif
		return NULL;

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
#ifdef USE_NEW_DES_API
	DES_cbc_encrypt((void *)data->v, (void *)res->v, data->l,
			&ks, (void *)iv->v, DES_ENCRYPT);
#else
	des_cbc_encrypt((void *)data->v, (void *)res->v, data->l,
			ks, (void *)iv->v, DES_ENCRYPT);
#endif

	return res;
}

rc_vchar_t *
eay_des_decrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
#ifdef USE_NEW_DES_API
	DES_key_schedule ks;
#else
	des_key_schedule ks;
#endif

#ifdef USE_NEW_DES_API
	if (DES_key_sched((void *)key->v, &ks) != 0)
#else
	if (des_key_sched((void *)key->v, ks) != 0)
#endif
		return NULL;

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
#ifdef USE_NEW_DES_API
	DES_cbc_encrypt((void *)data->v, (void *)res->v, data->l,
			&ks, (void *)iv->v, DES_DECRYPT);
#else
	des_cbc_encrypt((void *)data->v, (void *)res->v, data->l,
			ks, (void *)iv->v, DES_DECRYPT);
#endif

	return res;
}

int
eay_des_weakkey(rc_vchar_t *key)
{
#ifdef USE_NEW_DES_API
	return DES_is_weak_key((void *)key->v);
#else
	return des_is_weak_key((void *)key->v);
#endif
}

int
eay_des_keylen(int len)
{
	if (len != 0 && len != 64)
		return -1;
	return 64;
}

#ifdef HAVE_OPENSSL_IDEA_H
/*
 * IDEA-CBC
 */
rc_vchar_t *
eay_idea_encrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	IDEA_KEY_SCHEDULE ks;

	idea_set_encrypt_key((unsigned char *)key->v, &ks);

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	idea_cbc_encrypt((unsigned char *)data->v, (unsigned char *)res->v,
			 data->l, &ks, (unsigned char *)iv->v, IDEA_ENCRYPT);

	return res;
}

rc_vchar_t *
eay_idea_decrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	IDEA_KEY_SCHEDULE ks, dks;

	idea_set_encrypt_key((unsigned char *)key->v, &ks);
	idea_set_decrypt_key(&ks, &dks);

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	idea_cbc_encrypt((unsigned char *)data->v, (unsigned char *)res->v,
			 data->l, &dks, (unsigned char *)iv->v, IDEA_DECRYPT);

	return res;
}

int
eay_idea_weakkey(rc_vchar_t *key)
{
	return 0;		/* XXX */
}

int
eay_idea_keylen(int len)
{
	if (len != 0 && len != 128)
		return -1;
	return 128;
}
#endif

/*
 * BLOWFISH-CBC
 */
rc_vchar_t *
eay_bf_encrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	BF_KEY ks;

	BF_set_key(&ks, key->l, (unsigned char *)key->v);

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	BF_cbc_encrypt((unsigned char *)data->v, (unsigned char *)res->v,
		       data->l, &ks, (unsigned char *)iv->v, BF_ENCRYPT);

	return res;
}

rc_vchar_t *
eay_bf_decrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	BF_KEY ks;

	BF_set_key(&ks, key->l, (unsigned char *)key->v);

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	BF_cbc_encrypt((unsigned char *)data->v, (unsigned char *)res->v,
		       data->l, &ks, (unsigned char *)iv->v, BF_DECRYPT);

	return res;
}

/*ARGSUSED*/
int
eay_bf_weakkey(rc_vchar_t *key)
{
	return 0;		/* XXX to be done. refer to RFC 2451 */
}

int
eay_bf_keylen(int len)
{
	if (len == 0)
		return 448;
	if (len < 40 || len > 448)
		return -1;
	return len;
}

#ifdef HAVE_OPENSSL_RC5_H
/*
 * RC5-CBC
 */
rc_vchar_t *
eay_rc5_encrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	RC5_32_KEY ks;

	/* in RFC 2451, there is information about the number of round. */
	RC5_32_set_key(&ks, key->l, (unsigned char *)key->v, 16);

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	RC5_32_cbc_encrypt((unsigned char *)data->v, (unsigned char *)res->v,
			   data->l, &ks, (unsigned char *)iv->v, RC5_ENCRYPT);

	return res;
}

rc_vchar_t *
eay_rc5_decrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	RC5_32_KEY ks;

	/* in RFC 2451, there is information about the number of round. */
	RC5_32_set_key(&ks, key->l, (unsigned char *)key->v, 16);

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	RC5_32_cbc_encrypt((unsigned char *)data->v, (unsigned char *)res->v,
			   data->l, &ks, (unsigned char *)iv->v, RC5_DECRYPT);

	return res;
}

int
eay_rc5_weakkey(rc_vchar_t *key)
{
	return 0;		/* No known weak keys when used with 16 rounds. */

}

int
eay_rc5_keylen(int len)
{
	if (len == 0)
		return 128;
	if (len < 40 || len > 2040)
		return -1;
	return len;
}
#endif

/*
 * 3DES-CBC
 */
rc_vchar_t *
eay_3des_encrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
#ifdef USE_NEW_DES_API
	DES_key_schedule ks1, ks2, ks3;
#else
	des_key_schedule ks1, ks2, ks3;
#endif

	if (key->l < 24)
		return NULL;

#ifdef USE_NEW_DES_API
	if (DES_key_sched((void *)key->v, &ks1) != 0)
		return NULL;
	if (DES_key_sched((void *)(key->v + 8), &ks2) != 0)
		return NULL;
	if (DES_key_sched((void *)(key->v + 16), &ks3) != 0)
		return NULL;
#else
	if (des_key_sched((void *)key->v, ks1) != 0)
		return NULL;
	if (des_key_sched((void *)(key->v + 8), ks2) != 0)
		return NULL;
	if (des_key_sched((void *)(key->v + 16), ks3) != 0)
		return NULL;
#endif

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
#ifdef USE_NEW_DES_API
	DES_ede3_cbc_encrypt((void *)data->v, (void *)res->v, data->l,
			     &ks1, &ks2, &ks3, (void *)iv->v, DES_ENCRYPT);
#else
	des_ede3_cbc_encrypt((void *)data->v, (void *)res->v, data->l,
			     ks1, ks2, ks3, (void *)iv->v, DES_ENCRYPT);
#endif

	return res;
}

rc_vchar_t *
eay_3des_decrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
#ifdef USE_NEW_DES_API
	DES_key_schedule ks1, ks2, ks3;
#else
	des_key_schedule ks1, ks2, ks3;
#endif

	if (key->l < 24)
		return NULL;

#ifdef USE_NEW_DES_API
	if (DES_key_sched((void *)key->v, &ks1) != 0)
		return NULL;
	if (DES_key_sched((void *)(key->v + 8), &ks2) != 0)
		return NULL;
	if (DES_key_sched((void *)(key->v + 16), &ks3) != 0)
		return NULL;
#else
	if (des_key_sched((void *)key->v, ks1) != 0)
		return NULL;
	if (des_key_sched((void *)(key->v + 8), ks2) != 0)
		return NULL;
	if (des_key_sched((void *)(key->v + 16), ks3) != 0)
		return NULL;
#endif

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
#ifdef USE_NEW_DES_API
	DES_ede3_cbc_encrypt((void *)data->v, (void *)res->v, data->l,
			     &ks1, &ks2, &ks3, (void *)iv->v, DES_DECRYPT);
#else
	des_ede3_cbc_encrypt((void *)data->v, (void *)res->v, data->l,
			     ks1, ks2, ks3, (void *)iv->v, DES_DECRYPT);
#endif

	return res;
}

int
eay_3des_weakkey(rc_vchar_t *key)
{
	if (key->l < 24)
		return 0;

#ifdef USE_NEW_DES_API
	return (DES_is_weak_key((void *)key->v) ||
		DES_is_weak_key((void *)(key->v + 8)) ||
		DES_is_weak_key((void *)(key->v + 16)));
#else
	return (des_is_weak_key((void *)key->v) ||
		des_is_weak_key((void *)(key->v + 8)) ||
		des_is_weak_key((void *)(key->v + 16)));
#endif
}

int
eay_3des_keylen(int len)
{
	if (len != 0 && len != 192)
		return -1;
	return 192;
}

/*
 * CAST-CBC
 */
rc_vchar_t *
eay_cast_encrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	CAST_KEY ks;

	CAST_set_key(&ks, key->l, (unsigned char *)key->v);

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	CAST_cbc_encrypt((unsigned char *)data->v, (unsigned char *)res->v,
			 data->l, &ks, (unsigned char *)iv->v, DES_ENCRYPT);

	return res;
}

rc_vchar_t *
eay_cast_decrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *res;
	CAST_KEY ks;

	CAST_set_key(&ks, key->l, (unsigned char *)key->v);

	/* allocate buffer for result */
	if ((res = rc_vmalloc(data->l)) == NULL)
		return NULL;

	/* decryption data */
	CAST_cbc_encrypt((unsigned char *)data->v, (unsigned char *)res->v,
			 data->l, &ks, (unsigned char *)iv->v, DES_DECRYPT);

	return res;
}

/*ARGSUSED*/
int
eay_cast_weakkey(rc_vchar_t *key)
{
	return 0;		/* No known weak keys. */
}

int
eay_cast_keylen(int len)
{
	if (len == 0)
		return 128;
	if (len < 40 || len > 128)
		return -1;
	return len;
}

/*
 * AES(RIJNDAEL)-CBC
 */
rc_vchar_t *
eay_aes_encrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	const EVP_CIPHER *ciph;

	switch (key->l) {
	case 128 / 8:
		ciph = EVP_aes_128_cbc();
		break;
	case 192 / 8:
		ciph = EVP_aes_192_cbc();
		break;
	case 256 / 8:
		ciph = EVP_aes_256_cbc();
		break;
	default:
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "unsupported key length %lu\n", (unsigned long)key->l * 8);
		return NULL;
		break;
	}

	return evp_encrypt(ciph, data, key, iv);
}

rc_vchar_t *
eay_aes_decrypt(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	const EVP_CIPHER *ciph;

	switch (key->l) {
	case 128 / 8:
		ciph = EVP_aes_128_cbc();
		break;
	case 192 / 8:
		ciph = EVP_aes_192_cbc();
		break;
	case 256 / 8:
		ciph = EVP_aes_256_cbc();
		break;
	default:
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "unsupported key length %lu\n", (unsigned long)key->l * 8);
		return NULL;
		break;
	}

	return evp_decrypt(ciph, data, key, iv);
}

/*ARGSUSED*/
int
eay_aes_weakkey(rc_vchar_t *key)
{
	return 0;
}

int
eay_aes_keylen(int len)
{
	if (len != 128 && len != 192 && len != 256)
		return -1;
	return len;
}

/*
 * AES-CTR
 */
rc_vchar_t *
eay_aes_ctr(rc_vchar_t *data, rc_vchar_t *key, rc_vchar_t *iv)
{
	/* there's no difference of encrypt and decrypt for AES-CTR */

	/* (rfc3686)
	 * The size of the requested KEYMAT MUST be four octets longer than is
	 * needed for the associated AES key.  The keying material is used as
	 * follows:
	 * 
	 * AES-CTR with a 128 bit key
	 * The KEYMAT requested for each AES-CTR key is 20 octets.  The first
	 * 16 octets are the 128-bit AES key, and the remaining four octets
	 * are used as the nonce value in the counter block.
	 * 
	 * AES-CTR with a 192 bit key
	 * The KEYMAT requested for each AES-CTR key is 28 octets.  The first
	 * 24 octets are the 192-bit AES key, and the remaining four octets
	 * are used as the nonce value in the counter block.
	 * 
	 * AES-CTR with a 256 bit key
	 * The KEYMAT requested for each AES-CTR key is 36 octets.  The first
	 * 32 octets are the 256-bit AES key, and the remaining four octets
	 * are used as the nonce value in the counter block.
	 */

	uint8_t *nonce;
	union {
		uint8_t bytes[AES_BLOCK_SIZE];
		struct aes_ctrblk {
			uint32_t nonce;
			uint8_t iv[AES_CTR_IV_SIZE];
			uint32_t block_counter;
		} fields;
	} ctrblk;
	uint8_t ecount_buf[AES_BLOCK_SIZE];
	AES_KEY k;
	unsigned int num;
	rc_vchar_t *resultbuf;

	/*
	 * if (data->l > AES_BLOCK_SIZE * UINT32_MAX) return 0;
	 */

	if (iv->l != AES_CTR_IV_SIZE)
		return 0;
	nonce = (unsigned char *)key->v + key->l - AES_CTR_NONCE_SIZE;
	if (AES_set_encrypt_key((unsigned char *)key->v,
				(key->l - AES_CTR_NONCE_SIZE) << 3, &k) < 0)
		return 0;

	resultbuf = rc_vmalloc(data->l);
	if (!resultbuf)
		return 0;

	memcpy(&ctrblk.fields.nonce, nonce, AES_CTR_NONCE_SIZE);
	memcpy(&ctrblk.fields.iv[0], iv->v, AES_CTR_IV_SIZE);
	ctrblk.fields.block_counter = htonl(1);

	num = 0;
	AES_ctr128_encrypt((unsigned char *)data->v,
			   (unsigned char *)resultbuf->v, data->l, &k,
			   &ctrblk.bytes[0], ecount_buf, &num);

	return resultbuf;
}

/* for ipsec part */
int
eay_null_hashlen(void)
{
	return 0;
}

int
eay_kpdk_hashlen(void)
{
	return 0;
}

int
eay_twofish_keylen(int len)
{
	if (len < 0 || len > 256)
		return -1;
	return len;
}

/*ARGSUSED*/
int
eay_null_keylen(int len)
{
	return 0;
}

/*
 * HMAC functions
 */
static caddr_t
eay_hmac_init(rc_vchar_t *key, const EVP_MD *md)
{
	HMAC_CTX *c = racoon_malloc(sizeof(*c));

#if OPENSSL_VERSION_NUMBER < 0x0090700fL
	HMAC_Init(c, key->v, key->l, md);
#else
	HMAC_CTX_init(c);
	HMAC_Init_ex(c, key->v, key->l, md, NULL);
#endif

	return (caddr_t)c;
}

void
eay_hmac_dispose(HMAC_CTX *c)
{
#if OPENSSL_VERSION_NUMBER < 0x0090700fL
	HMAC_cleanup(c);
#else
	HMAC_CTX_cleanup(c);
#endif
	(void)racoon_free(c);
}

#ifdef WITH_SHA2
/*
 * HMAC SHA2-512
 */
rc_vchar_t *
eay_hmacsha2_512_one(rc_vchar_t *key, rc_vchar_t *data)
{
	rc_vchar_t *res;
	caddr_t ctx;

	ctx = eay_hmacsha2_512_init(key);
	eay_hmacsha2_512_update(ctx, data);
	res = eay_hmacsha2_512_final(ctx);

	return (res);
}

caddr_t
eay_hmacsha2_512_init(rc_vchar_t *key)
{
	return eay_hmac_init(key, EVP_sha512());
}

void
eay_hmacsha2_512_update(caddr_t c, rc_vchar_t *data)
{
	HMAC_Update((HMAC_CTX *)c, (unsigned char *)data->v, data->l);
}

rc_vchar_t *
eay_hmacsha2_512_final(caddr_t c)
{
	rc_vchar_t *res;
	unsigned int l;

	if ((res = rc_vmalloc(SHA512_DIGEST_LENGTH)) == 0)
		return NULL;

	HMAC_Final((HMAC_CTX *)c, (unsigned char *)res->v, &l);
	res->l = l;
	eay_hmac_dispose((HMAC_CTX *)c);

	if (SHA512_DIGEST_LENGTH != res->l) {
#ifndef EAYDEBUG
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "hmac sha2_512 length mismatch %lu.\n", (unsigned long)res->l);
#else
		printf("hmac sha2_512 length mismatch %lu.\n", (unsigned long)res->l);
#endif
		rc_vfree(res);
		return NULL;
	}

	return (res);
}

/*
 * HMAC SHA2-384
 */
rc_vchar_t *
eay_hmacsha2_384_one(rc_vchar_t *key, rc_vchar_t *data)
{
	rc_vchar_t *res;
	caddr_t ctx;

	ctx = eay_hmacsha2_384_init(key);
	eay_hmacsha2_384_update(ctx, data);
	res = eay_hmacsha2_384_final(ctx);

	return (res);
}

caddr_t
eay_hmacsha2_384_init(rc_vchar_t *key)
{
	return eay_hmac_init(key, EVP_sha384());
}

void
eay_hmacsha2_384_update(caddr_t c, rc_vchar_t *data)
{
	HMAC_Update((HMAC_CTX *)c, (unsigned char *)data->v, data->l);
}

rc_vchar_t *
eay_hmacsha2_384_final(caddr_t c)
{
	rc_vchar_t *res;
	unsigned int l;

	if ((res = rc_vmalloc(SHA384_DIGEST_LENGTH)) == 0)
		return NULL;

	HMAC_Final((HMAC_CTX *)c, (unsigned char *)res->v, &l);
	res->l = l;
	eay_hmac_dispose((HMAC_CTX *)c);

	if (SHA384_DIGEST_LENGTH != res->l) {
#ifndef EAYDEBUG
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "hmac sha2_384 length mismatch %lu.\n", (unsigned long)res->l);
#else
		printf("hmac sha2_384 length mismatch %lu.\n", (unsigned long)res->l);
#endif
		rc_vfree(res);
		return NULL;
	}

	return (res);
}

/*
 * HMAC SHA2-256
 */
rc_vchar_t *
eay_hmacsha2_256_one(rc_vchar_t *key, rc_vchar_t *data)
{
	rc_vchar_t *res;
	caddr_t ctx;

	ctx = eay_hmacsha2_256_init(key);
	eay_hmacsha2_256_update(ctx, data);
	res = eay_hmacsha2_256_final(ctx);

	return (res);
}

caddr_t
eay_hmacsha2_256_init(rc_vchar_t *key)
{
	return eay_hmac_init(key, EVP_sha256());
}

void
eay_hmacsha2_256_update(caddr_t c, rc_vchar_t *data)
{
	HMAC_Update((HMAC_CTX *)c, (unsigned char *)data->v, data->l);
}

rc_vchar_t *
eay_hmacsha2_256_final(caddr_t c)
{
	rc_vchar_t *res;
	unsigned int l;

	if ((res = rc_vmalloc(SHA256_DIGEST_LENGTH)) == 0)
		return NULL;

	HMAC_Final((HMAC_CTX *)c, (unsigned char *)res->v, &l);
	res->l = l;
	eay_hmac_dispose((HMAC_CTX *)c);

	if (SHA256_DIGEST_LENGTH != res->l) {
#ifndef EAYDEBUG
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "hmac sha2_256 length mismatch %lu.\n", (unsigned long)res->l);
#else
		printf("hmac sha2_256 length mismatch %lu.\n", (unsigned long)res->l);
#endif
		rc_vfree(res);
		return NULL;
	}

	return (res);
}
#endif				/* WITH_SHA2 */

/*
 * HMAC SHA1
 */
rc_vchar_t *
eay_hmacsha1_one(rc_vchar_t *key, rc_vchar_t *data)
{
	rc_vchar_t *res;
	caddr_t ctx;

	ctx = eay_hmacsha1_init(key);
	eay_hmacsha1_update(ctx, data);
	res = eay_hmacsha1_final(ctx);

	return (res);
}

caddr_t
eay_hmacsha1_init(rc_vchar_t *key)
{
	return eay_hmac_init(key, EVP_sha1());
}

void
eay_hmacsha1_update(caddr_t c, rc_vchar_t *data)
{
	HMAC_Update((HMAC_CTX *)c, (unsigned char *)data->v, data->l);
}

rc_vchar_t *
eay_hmacsha1_final(caddr_t c)
{
	rc_vchar_t *res;
	unsigned int l;

	if ((res = rc_vmalloc(SHA_DIGEST_LENGTH)) == 0)
		return NULL;

	HMAC_Final((HMAC_CTX *)c, (unsigned char *)res->v, &l);
	res->l = l;
	eay_hmac_dispose((HMAC_CTX *)c);

	if (SHA_DIGEST_LENGTH != res->l) {
#ifndef EAYDEBUG
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "hmac sha1 length mismatch %lu.\n", (unsigned long)res->l);
#else
		printf("hmac sha1 length mismatch %lu.\n", (unsigned long)res->l);
#endif
		rc_vfree(res);
		return NULL;
	}

	return (res);
}

/*
 * HMAC MD5
 */
rc_vchar_t *
eay_hmacmd5_one(rc_vchar_t *key, rc_vchar_t *data)
{
	rc_vchar_t *res;
	caddr_t ctx;

	ctx = eay_hmacmd5_init(key);
	eay_hmacmd5_update(ctx, data);
	res = eay_hmacmd5_final(ctx);

	return (res);
}

caddr_t
eay_hmacmd5_init(rc_vchar_t *key)
{
	return eay_hmac_init(key, EVP_md5());
}

void
eay_hmacmd5_update(caddr_t c, rc_vchar_t *data)
{
	HMAC_Update((HMAC_CTX *)c, (unsigned char *)data->v, data->l);
}

rc_vchar_t *
eay_hmacmd5_final(caddr_t c)
{
	rc_vchar_t *res;
	unsigned int l;

	if ((res = rc_vmalloc(MD5_DIGEST_LENGTH)) == 0)
		return NULL;

	HMAC_Final((HMAC_CTX *)c, (unsigned char *)res->v, &l);
	res->l = l;
	eay_hmac_dispose((HMAC_CTX *)c);

	if (MD5_DIGEST_LENGTH != res->l) {
#ifndef EAYDEBUG
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "hmac md5 length mismatch %lu.\n", (unsigned long)res->l);
#else
		printf("hmac md5 length mismatch %lu.\n", (unsigned long)res->l);
#endif
		rc_vfree(res);
		return NULL;
	}

	return (res);
}

/*
 * AES-XCBC-PRF-128 (RFC3664)
 */
#define	REPEAT4(x_)	x_, x_, x_, x_
#define	REPEAT16(x_)	REPEAT4(x_), REPEAT4(x_), REPEAT4(x_), REPEAT4(x_)

typedef struct aescbcmac_ctx {
	AES_KEY k1;
	uint8_t k2[AES_XCBC_BLOCKLEN];
	uint8_t k3[AES_XCBC_BLOCKLEN];
	uint8_t e[AES_XCBC_BLOCKLEN];
	uint8_t m[AES_XCBC_BLOCKLEN];
	int mlen;
} CBCMAC_CTX;

#if 0
typedef struct cbcmac_ctx {
	caddr_t *k1;
	void (*encrypt) ();
	void (*dispose_k1) ();
	uint8_t k2[MAX_CBCMAC_BLOCKLEN];
	uint8_t k3[MAX_CBCMAC_BLOCKLEN];
	uint8_t e[MAX_CBCMAC_BLOCKLEN];
	uint8_t m[MAX_CBCMAC_BLOCKLEN];
	int mlen;
};
#endif

/*
 * AES-XCBC-MAC (RFC3664) / AES-XCBC-PRF-128 (RFC4434)
 */
int
eay_aes_xcbc_mac_keylen(int len)
{
	if (len == 0)
		return AES_XCBC_KEYLEN;
	if (len != AES_XCBC_KEYLEN)
		return -1;
	return len;
}

int
eay_aes_xcbc_hashlen(void)
{
	return AES_XCBC_BLOCKLEN << 3;
}

caddr_t
eay_aes_xcbc_mac_init(rc_vchar_t *key)
{
	rc_vchar_t	*k = 0;
	CBCMAC_CTX *c = 0;
	AES_KEY aes_key;
	uint8_t k1[AES_XCBC_BLOCKLEN];
	static const uint8_t const1[] = { REPEAT16(0x01) };
	static const uint8_t const2[] = { REPEAT16(0x02) };
	static const uint8_t const3[] = { REPEAT16(0x03) };
	const size_t aesxcbc_keylen = AES_XCBC_KEYLEN / 8;

	if (key->l == aesxcbc_keylen) {
		k = rc_vdup(key);
	} else if (key->l < aesxcbc_keylen) {
		k = rc_vmalloc(aesxcbc_keylen);
		if (!k) 
			return 0;
		memcpy(k->v, key->v, key->l);
		memset(k->v + key->l, 0, k->l - key->l);
	} else {
		static uint8_t zerokey_bits[] = { REPEAT16(0) };
		static rc_vchar_t zerokey = VCHAR_INIT((caddr_t)zerokey_bits,
						       sizeof(zerokey_bits));

		k = eay_aes_xcbc_mac_one(&zerokey, key);
	}
	if (!k)
		return 0;

	if (AES_set_encrypt_key((unsigned char *)k->v, k->l * 8, &aes_key)
	    != 0)
		goto fail;
	c = racoon_malloc(sizeof(*c));
	if (!c)
		goto fail;
	AES_encrypt(const1, k1, &aes_key);
	if (AES_set_encrypt_key(k1, 128, &c->k1) != 0)
		goto fail;
	AES_encrypt(const2, c->k2, &aes_key);
	AES_encrypt(const3, c->k3, &aes_key);
	memset(c->e, 0, sizeof(c->e));
	c->mlen = 0;

	rc_vfree(k);
	return (caddr_t)c;

      fail:
	if (c)
		racoon_free(c);
	if (k)
		rc_vfree(k);
	return 0;
}

void
eay_aes_xcbc_mac_update(caddr_t ctx, rc_vchar_t *data)
{
	CBCMAC_CTX *c = (CBCMAC_CTX *)ctx;
	unsigned char *p;
	int i;
	size_t len;
	size_t l;

	len = data->l;
	p = (unsigned char *)data->v;
	while (len > 0) {
		assert(c->mlen <= AES_XCBC_BLOCKLEN);
		if (c->mlen == AES_XCBC_BLOCKLEN) {
			for (i = 0; i < AES_XCBC_BLOCKLEN; ++i)
				c->m[i] ^= c->e[i];
			AES_encrypt(c->m, c->e, &c->k1);
			c->mlen = 0;
		}
		l = len;
		if (l > (size_t)AES_XCBC_BLOCKLEN - c->mlen)
			l = AES_XCBC_BLOCKLEN - c->mlen;
		memcpy(&c->m[c->mlen], p, l);
		c->mlen += l;
		len -= l;
		p += l;
	}
}

void
eay_aes_xcbc_mac_dispose(caddr_t ctx)
{
	CBCMAC_CTX *c = (CBCMAC_CTX *)ctx;

	memset(c, 0, sizeof(*c));
	racoon_free(c);
}

rc_vchar_t *
eay_aes_xcbc_mac_final(caddr_t ctx)
{
	CBCMAC_CTX *c = (CBCMAC_CTX *)ctx;
	int i;
	rc_vchar_t *result;

	if (c->mlen == AES_XCBC_BLOCKLEN) {
		for (i = 0; i < AES_XCBC_BLOCKLEN; ++i)
			c->m[i] ^= c->e[i] ^ c->k2[i];
	} else {
		c->m[c->mlen] = 0x80;
		for (i = c->mlen + 1; i < AES_XCBC_BLOCKLEN; ++i)
			c->m[i] = 0;
		for (i = 0; i < AES_XCBC_BLOCKLEN; ++i)
			c->m[i] ^= c->e[i] ^ c->k3[i];
	}
	AES_encrypt(c->m, c->e, &c->k1);

	result = rc_vmalloc(AES_XCBC_BLOCKLEN);
	if (!result)
		return 0;
	memcpy(result->v, c->e, AES_XCBC_BLOCKLEN);

	eay_aes_xcbc_mac_dispose(ctx);

	return result;
}

rc_vchar_t *
eay_aes_xcbc_mac_one(rc_vchar_t *key, rc_vchar_t *data)
{
	rc_vchar_t *res;
	caddr_t ctx;

	ctx = eay_aes_xcbc_mac_init(key);
	eay_aes_xcbc_mac_update(ctx, data);
	res = eay_aes_xcbc_mac_final(ctx);

	return (res);
}

/*
 * CMAC (FIPS SP800-38B)
 * (RFC4615)
 */
static void
gf_mult(uint8_t *l, uint8_t *k, unsigned int r)
{
	int i;
	int value;
	int carryover;

	/*
	 * if (MSB(L) == 0
	 *    { L <<= 1         }
	 * else
	 *    { L <<= 1; L ^= R }
	 */
	carryover = 0;
	for (i = AES_BLOCK_SIZE; --i >= 0;) {
		value = l[i] << 1;
		k[i] = value | carryover;
		carryover = value >> 8;
	}
	if (carryover)
		k[AES_BLOCK_SIZE - 1] ^= r;
}

caddr_t
eay_aes_cmac_init(rc_vchar_t *key)
{
	rc_vchar_t *k = 0;
	CBCMAC_CTX *c = 0;
	static const uint8_t zero[AES_BLOCK_SIZE] = { REPEAT16(0) };
	static const uint8_t R128 = 0x87;
	uint8_t L[AES_BLOCK_SIZE];
	const size_t aescmac_keylen = 128 / 8;

	if (key->l == aescmac_keylen) {
		k = rc_vdup(key);
	} else if (key->l < aescmac_keylen) {
		k = rc_vmalloc(aescmac_keylen);
		if (!k) 
			return 0;
		memcpy(k->v, key->v, key->l);
		memset(k->v + key->l, 0, k->l - key->l);
	} else {
		static uint8_t zerokey_bits[] = { REPEAT16(0) };
		static rc_vchar_t zerokey = VCHAR_INIT((caddr_t)zerokey_bits,
						       sizeof(zerokey_bits));

		k = eay_aes_cmac_one(&zerokey, key);
	}
	if (!k)
		return 0;

	c = racoon_calloc(1, sizeof(*c));
	if (!c)
		goto fail;

	if (AES_set_encrypt_key((unsigned char *)key->v, key->l * 8, &c->k1)
	    != 0)
		goto fail;
	AES_encrypt(zero, L, &c->k1);
	//gf_mult(L, &c->k2, R128);
	//gf_mult(&c->k2, &c->k3, R128);
	gf_mult(L, c->k2, R128);
	gf_mult(c->k2, c->k3, R128);

	return (caddr_t)c;

      fail:
	if (c)
		racoon_free(c);
	if (k)
		racoon_free(k);
	return 0;
}

void
eay_aes_cmac_update(caddr_t ctx, rc_vchar_t *data)
{
	eay_aes_xcbc_mac_update(ctx, data);
}

void
eay_aes_cmac_dispose(caddr_t ctx)
{
	eay_aes_xcbc_mac_dispose(ctx);
}

rc_vchar_t *
eay_aes_cmac_final(caddr_t ctx)
{
	return eay_aes_xcbc_mac_final(ctx);
}

rc_vchar_t *
eay_aes_cmac_one(rc_vchar_t *key, rc_vchar_t *data)
{
	rc_vchar_t *res;
	caddr_t ctx;

	ctx = eay_aes_cmac_init(key);
	eay_aes_cmac_update(ctx, data);
	res = eay_aes_cmac_final(ctx);

	return (res);
}

int
eay_aes_cmac_hashlen(void)
{
	return AES_XCBC_BLOCKLEN << 3;
}

#ifdef WITH_SHA2
/*
 * SHA2-512 functions
 */
caddr_t
eay_sha2_512_init(void)
{
	SHA512_CTX *c = racoon_malloc(sizeof(*c));

	SHA512_Init(c);

	return ((caddr_t)c);
}

void
eay_sha2_512_update(caddr_t c, rc_vchar_t *data)
{
	SHA512_Update((SHA512_CTX *)c, (unsigned char *)data->v, data->l);

	return;
}

rc_vchar_t *
eay_sha2_512_final(caddr_t c)
{
	rc_vchar_t *res;

	if ((res = rc_vmalloc(SHA512_DIGEST_LENGTH)) == 0)
		return (0);

	SHA512_Final((unsigned char *)res->v, (SHA512_CTX *)c);
	(void)racoon_free(c);

	return (res);
}

rc_vchar_t *
eay_sha2_512_one(rc_vchar_t *data)
{
	caddr_t ctx;
	rc_vchar_t *res;

	ctx = eay_sha2_512_init();
	eay_sha2_512_update(ctx, data);
	res = eay_sha2_512_final(ctx);

	return (res);
}
#endif

int
eay_sha2_512_hashlen(void)
{
	return SHA512_DIGEST_LENGTH << 3;
}

#ifdef WITH_SHA2
/*
 * SHA2-384 functions
 */
caddr_t
eay_sha2_384_init(void)
{
	SHA384_CTX *c = racoon_malloc(sizeof(*c));

	SHA384_Init(c);

	return ((caddr_t)c);
}

void
eay_sha2_384_update(caddr_t c, rc_vchar_t *data)
{
	SHA384_Update((SHA384_CTX *)c, (unsigned char *)data->v, data->l);

	return;
}

rc_vchar_t *
eay_sha2_384_final(caddr_t c)
{
	rc_vchar_t *res;

	if ((res = rc_vmalloc(SHA384_DIGEST_LENGTH)) == 0)
		return (0);

	SHA384_Final((unsigned char *)res->v, (SHA384_CTX *)c);
	(void)racoon_free(c);

	return (res);
}

rc_vchar_t *
eay_sha2_384_one(rc_vchar_t *data)
{
	caddr_t ctx;
	rc_vchar_t *res;

	ctx = eay_sha2_384_init();
	eay_sha2_384_update(ctx, data);
	res = eay_sha2_384_final(ctx);

	return (res);
}
#endif

int
eay_sha2_384_hashlen(void)
{
	return SHA384_DIGEST_LENGTH << 3;
}

#ifdef WITH_SHA2
/*
 * SHA2-256 functions
 */
caddr_t
eay_sha2_256_init(void)
{
	SHA256_CTX *c = racoon_malloc(sizeof(*c));

	SHA256_Init(c);

	return ((caddr_t)c);
}

void
eay_sha2_256_update(caddr_t c, rc_vchar_t *data)
{
	SHA256_Update((SHA256_CTX *)c, (unsigned char *)data->v, data->l);

	return;
}

rc_vchar_t *
eay_sha2_256_final(caddr_t c)
{
	rc_vchar_t *res;

	if ((res = rc_vmalloc(SHA256_DIGEST_LENGTH)) == 0)
		return (0);

	SHA256_Final((unsigned char *)res->v, (SHA256_CTX *)c);
	(void)racoon_free(c);

	return (res);
}

rc_vchar_t *
eay_sha2_256_one(rc_vchar_t *data)
{
	caddr_t ctx;
	rc_vchar_t *res;

	ctx = eay_sha2_256_init();
	eay_sha2_256_update(ctx, data);
	res = eay_sha2_256_final(ctx);

	return (res);
}
#endif

int
eay_sha2_256_hashlen(void)
{
	return SHA256_DIGEST_LENGTH << 3;
}

/*
 * SHA functions
 */
caddr_t
eay_sha1_init(void)
{
	EVP_MD_CTX *c;

	c = EVP_MD_CTX_create();
	if (!EVP_DigestInit_ex(c, EVP_sha1(), NULL)) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "EVP_DigestInit_ex failed: %s\n", eay_strerror());
		EVP_MD_CTX_destroy(c);
		return 0;
	}
	return (caddr_t)c;
}

void
eay_sha1_update(caddr_t c, rc_vchar_t *data)
{
	EVP_MD_CTX *ctx = (EVP_MD_CTX *)c;

	if (!EVP_DigestUpdate(ctx, data->v, data->l)) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "EVP_DigestUpdate failed: %s\n", eay_strerror());
		return;
	}
	return;
}

rc_vchar_t *
eay_sha1_final(caddr_t c)
{
	EVP_MD_CTX *ctx = (EVP_MD_CTX *)c;
	rc_vchar_t *res;

	if ((res = rc_vmalloc(SHA_DIGEST_LENGTH)) == 0)
		return (0);

	if (!EVP_DigestFinal(ctx, (unsigned char *)res->v, NULL)) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "EVP_DigestFinal failed: %s\n", eay_strerror());
		rc_vfree(res);
		res = 0;
	}
	EVP_MD_CTX_destroy(ctx);
	return res;
}

rc_vchar_t *
eay_sha1_one(rc_vchar_t *data)
{
	caddr_t ctx;
	rc_vchar_t *res;

	ctx = eay_sha1_init();
	eay_sha1_update(ctx, data);
	res = eay_sha1_final(ctx);

	return (res);
}

int
eay_sha1_hashlen(void)
{
	return SHA_DIGEST_LENGTH << 3;
}

/*
 * MD5 functions
 */
caddr_t
eay_md5_init(void)
{
	EVP_MD_CTX *c;

	c = EVP_MD_CTX_create();
	if (!EVP_DigestInit_ex(c, EVP_md5(), NULL)) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "EVP_DigestInit_ex failed: %s\n", eay_strerror());
		EVP_MD_CTX_destroy(c);
		return 0;
	}
	return (caddr_t)c;
}

void
eay_md5_update(caddr_t c, rc_vchar_t *data)
{
	EVP_MD_CTX *ctx = (EVP_MD_CTX *)c;

	if (!EVP_DigestUpdate(ctx, data->v, data->l)) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "EVP_DigestUpdate failed: %s\n", eay_strerror());
		return;
	}
	return;
}

rc_vchar_t *
eay_md5_final(caddr_t c)
{
	EVP_MD_CTX *ctx = (EVP_MD_CTX *)c;
	rc_vchar_t *res;

	if ((res = rc_vmalloc(MD5_DIGEST_LENGTH)) == 0)
		return (0);

	if (!EVP_DigestFinal(ctx, (unsigned char *)res->v, NULL)) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "EVP_DigestFinal failed: %s\n", eay_strerror());
		rc_vfree(res);
		res = 0;
	}
	EVP_MD_CTX_destroy(ctx);
	return res;
}

rc_vchar_t *
eay_md5_one(rc_vchar_t *data)
{
	caddr_t ctx;
	rc_vchar_t *res;

	ctx = eay_md5_init();
	eay_md5_update(ctx, data);
	res = eay_md5_final(ctx);

	return (res);
}

int
eay_md5_hashlen(void)
{
	return MD5_DIGEST_LENGTH << 3;
}

/*
 * eay_set_random
 *   size: number of bytes.
 */
rc_vchar_t *
eay_set_random(uint32_t size)
{
	rc_vchar_t *result;

	result = rc_vmalloc(size);
	if (!result)
		return 0;
	if (RAND_bytes((unsigned char *)result->v, result->l) != 1) {
#ifdef EAYDEBUG
		printf("failed to generate random number, code %lu\n",
		       ERR_get_error());
#else
		plog(PLOG_DEBUG, PLOGLOC, NULL,
		     "failed to generate random number, code %lu\n",
		     ERR_get_error());
#endif
		rc_vfree(result);
		return 0;
	}
	return result;
}

uint32_t
eay_random_uint32(void)
{
	uint32_t value;
	(void)RAND_pseudo_bytes((uint8_t *)&value, sizeof(value));
	return value;
}

/* DH */
int
eay_dh_generate(rc_vchar_t *prime, uint32_t g, unsigned int publen, rc_vchar_t **pub, rc_vchar_t **priv)
{
	BIGNUM *p = NULL;
	DH *dh = NULL;
	int error = -1;

	/* initialize */
	/* pre-process to generate number */
	if (eay_v2bn(&p, prime) < 0)
		goto end;

	if ((dh = DH_new()) == NULL)
		goto end;
	dh->p = p;
	p = NULL;		/* p is now part of dh structure */
	dh->g = NULL;
	if ((dh->g = BN_new()) == NULL)
		goto end;
	if (!BN_set_word(dh->g, g))
		goto end;

	if (publen != 0)
		dh->length = publen;

	/* generate public and private number */
	if (!DH_generate_key(dh))
		goto end;

	/* copy results to buffers */
	if (eay_bn2v(pub, dh->pub_key) < 0)
		goto end;
	if (eay_bn2v(priv, dh->priv_key) < 0) {
		rc_vfree(*pub);
		goto end;
	}

	error = 0;

      end:
	if (dh != NULL)
		DH_free(dh);
	if (p != 0)
		BN_free(p);
	return (error);
}

int 
eay_dh_compute (rc_vchar_t *prime, uint32_t g, rc_vchar_t *pub, 
		rc_vchar_t *priv, rc_vchar_t *pub2, rc_vchar_t **key)
{
	BIGNUM *dh_pub = NULL;
	DH *dh = NULL;
	int l;
	unsigned char *v = NULL;
	int error = -1;

	/* make public number to compute */
	if (eay_v2bn(&dh_pub, pub2) < 0)
		goto end;

	/* make DH structure */
	if ((dh = DH_new()) == NULL)
		goto end;
	if (eay_v2bn(&dh->p, prime) < 0)
		goto end;
	if (eay_v2bn(&dh->pub_key, pub) < 0)
		goto end;
	if (eay_v2bn(&dh->priv_key, priv) < 0)
		goto end;
	dh->length = pub2->l * 8;

	dh->g = NULL;
	if ((dh->g = BN_new()) == NULL)
		goto end;
	if (!BN_set_word(dh->g, g))
		goto end;

	if ((v = racoon_calloc(prime->l, sizeof(unsigned char))) == NULL)
		goto end;
	if ((l = DH_compute_key(v, dh_pub, dh)) == -1)
		goto end;
	memcpy((*key)->v + (prime->l - l), v, l);

	error = 0;

      end:
	if (dh_pub != NULL)
		BN_free(dh_pub);
	if (dh != NULL)
		DH_free(dh);
	if (v != NULL)
		racoon_free(v);
	return (error);
}

int
eay_v2bn(BIGNUM **bn, rc_vchar_t *var)
{
	if ((*bn = BN_bin2bn((unsigned char *)var->v, var->l, NULL)) == NULL)
		return -1;

	return 0;
}

int
eay_bn2v(rc_vchar_t **var, BIGNUM *bn)
{
	*var = rc_vmalloc(bn->top * BN_BYTES);
	if (*var == NULL)
		return (-1);

	(*var)->l = BN_bn2bin(bn, (unsigned char *)(*var)->v);

	return 0;
}

const char *
eay_version(void)
{
	return SSLeay_version(SSLEAY_VERSION);
}

#ifdef SELFTEST
int
test_timegm(void)
{
	static struct {
		struct tm tm;
		time_t value;
	} testvec[] = {
		{ { 0, 0, 0, 2, 0, 70}, 86400},
		{ { 40, 46, 1, 9, 8, 101}, 1000000000},
		{ { 0, 0, 0, 1, 3, 105}, 1112313600},
	};
	int i;
	time_t result;
	int err = 0;

	for (i = 0; i < ARRAYLEN(testvec); ++i) {
		result = timegm(&testvec[i].tm);
		if (result != testvec[i].value) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "timegm selftest #%d failed (%ld != %ld)\n",
			     i, (long)result, (long)testvec[i].value);
			err = -1;
		}
	}
	return err;
}

int
test_utctime(void)
{
	static struct {
		time_t t;
		char *str;
	} testvec[] = {
		{ 86400, "700102000000Z"},
		{ 1000000000, "010909014640Z"},
		{ 1112313600, "050401000000Z"},
	};
	int i;
	struct timeval tv;
	ASN1_UTCTIME *utctime;
	int err = 0;

	for (i = 0; i < ARRAYLEN(testvec); ++i) {
		utctime = ASN1_UTCTIME_set(0, testvec[i].t);
		if (!utctime) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "utctime selftest #%d failed: ASN1_UTCTIME_set returned NULL\n",
			     i);
			err = -1;
			continue;
		}
		if (strncmp((char*)utctime->data, testvec[i].str, utctime->length) != 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "utctime selftest #%d failed: %.*s != %s\n",
			     i, (int)utctime->length, utctime->data,
			     testvec[i].str);
			err = -1;
		}
		if (eay_utctime(&tv, utctime) != 0 ||
		    tv.tv_sec != testvec[i].t) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "utctime selftest #%d failed (%ld != %ld, %s)\n",
			     i, (long)tv.tv_sec, (long)testvec[i].t, utctime->data);
			err = -1;
		}
		M_ASN1_UTCTIME_free(utctime);
	}
	return err;
}

int
test_generalizedtime(void)
{
	static struct {
		time_t t;
		char *str;
	} testvec[] = {
		{ 86400, "19700102000000Z"},
		{ 1000000000, "20010909014640Z"},
		{ 1112313600, "20050401000000Z"},
	};
	int i;
	struct timeval tv;
	ASN1_GENERALIZEDTIME *generalizedtime;
	int err = 0;

	for (i = 0; i < ARRAYLEN(testvec); ++i) {
		generalizedtime = ASN1_GENERALIZEDTIME_set(0, testvec[i].t);
		if (!generalizedtime) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "generalizedtime selftest #%d failed: ASN1_GENERALIZEDTIME_set returned NULL\n",
			     i);
			err = -1;
			continue;
		}
		if (strncmp((char*)generalizedtime->data, testvec[i].str,
		    generalizedtime->length) != 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "generalizedtime selftest #%d failed: %.*s != %s\n",
			     i, (int)generalizedtime->length,
			     generalizedtime->data, testvec[i].str);
			err = -1;
		}
		if (eay_generalizedtime(&tv, generalizedtime) != 0
		    || tv.tv_sec != testvec[i].t) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "generalizedtime selftest #%d failed (%ld != %ld, %s)\n",
			     i, (long)tv.tv_sec, (long)testvec[i].t, generalizedtime->data);
			err = -1;
		}
		M_ASN1_GENERALIZEDTIME_free(generalizedtime);
	}
	return err;
}

int
crypto_selftest(void)
{
	if (test_timegm() != 0)
		return -1;
	if (test_utctime() != 0)
		return -1;
	if (test_generalizedtime() != 0)
		return -1;
	return 0;
}
#endif

/*
 * Local Variables:
 * c-basic-offset: 8
 * End:
 */
