

#if OPENSSL_VERSION_NUMBER < 0x10100000L

/* evp.h */

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
    
#endif

