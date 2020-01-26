

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#include <openssl/evp.h>

static inline EVP_MD_CTX *EVP_MD_CTX_new(void)
{
        EVP_MD_CTX *ctx = malloc(sizeof(*ctx));
        if (ctx == NULL)
                return NULL;     
        EVP_MD_CTX_init(ctx);   
        return ctx;             
}   
    
static inline void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{   
        if (ctx == NULL)        
                return;         
        EVP_MD_CTX_cleanup(ctx);
        free(ctx);
}   
    
static inline RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey)
{ 
        if (pkey->type != EVP_PKEY_RSA)
            return NULL;
        return pkey->pkey.rsa;
}   
    
static inline DSA *EVP_PKEY_get0_DSA(EVP_PKEY *pkey)
{    
        if (pkey->type != EVP_PKEY_DSA) {
                return NULL;
        }
        return pkey->pkey.dsa;
}   

#include <openssl/dh.h>

static inline void
DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key)
{
	if (pub_key)
		*pub_key = dh->pub_key;
	if (priv_key)
		*priv_key = dh->priv_key;
}

static inline int
DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
{
	if (pub_key) {
		BN_free(dh->pub_key);
		dh->pub_key = pub_key;
	}
	if (priv_key) {
		BN_free(dh->priv_key);
		dh->priv_key = priv_key;
	}
	return 1;
}

static inline void
DH_get0_pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q,
    const BIGNUM **g)
{
	if (p)
		*p = dh->p;
	if (q)
		*q = dh->q;
	if (g)
		*g = dh->g;
}

static inline int
DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
	if (p)
		dh->p = p;
	if (q)
		dh->q = q;
	if (g)
		dh->g = g;
	return 1;
}

static inline void
DH_set_length(DH *dh, long length)
{
	dh->length = length;
}

static inline const char *
DH_meth_get0_name(const DH_METHOD *meth)
{
	return meth->name;
}   
    
#include <openssl/hmac.h>

static inline HMAC_CTX *HMAC_CTX_new(void)
{
	HMAC_CTX *ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL)
		return NULL;
	HMAC_CTX_init(ctx);
	return ctx;
}

static inline void HMAC_CTX_free(HMAC_CTX *ctx)
{
	if (ctx == NULL)
		return;
	HMAC_CTX_cleanup(ctx);
	free(ctx);
}

static inline void HMAC_CTX_reset(HMAC_CTX *ctx)
{
	HMAC_CTX_cleanup(ctx);
	HMAC_CTX_init(ctx);
}

#include <openssl/x509_vfy.h>

static inline X509 *
X509_STORE_CTX_get0_cert(X509_STORE_CTX *x)
{ 
	return X509_STORE_CTX_get_current_cert(x);
}

#endif
