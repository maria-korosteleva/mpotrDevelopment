#include <stdio.h>
#include <gcrypt.h>

void myprint(void);
void initLibgcrypt();
unsigned char* getSomeNonce(int length);
unsigned char* hash(unsigned char* str, int length);

void myprint()
{
    printf("hello world\n");
}

void generateKeys(char* pub_key, char* priv_key)
{
    gcry_sexp_t r_key, param;
    int err = gcry_sexp_build (&param, NULL, "(genkey (rsa (nbits 4:2048)))");
    if (err) {
        printf("gcrypt: failed to create dsa params\n");
    }
    printf("Param is %s\n", param);
    
    err = gcry_pk_genkey (&r_key, param);
    if (err) {
        printf("gcrypt: failed to create dsa keypair\n");
    }
    printf("Key is %s\n", r_key);
    int len = gcry_sexp_sprint(r_key, GCRYSEXP_FMT_CANON, NULL, 0);
    char* buffer = (char*) malloc ((len+1) * sizeof(char));
    gcry_sexp_sprint(r_key, GCRYSEXP_FMT_CANON, buffer, len+1);
    printf("%d, key is %s\n", len, buffer);
}


unsigned char* getSomeNonce(int length)
{
    unsigned char* buffer = (unsigned char*) gcry_malloc((length+1) * sizeof(char));
    buffer[length] = '\0';
    gcry_randomize (buffer, length, GCRY_STRONG_RANDOM);
    // void * gcry_random_bytes (size_t nbytes, enum gcry_random_level level);
    return buffer;
}


unsigned char* hash(unsigned char* str, int length)
{
    int hash_len = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
    unsigned char* digest = (unsigned char*) gcry_malloc(hash_len+1);
    digest[hash_len] = '\0';
    gcry_md_hash_buffer(GCRY_MD_SHA256, digest, str, length);
    return digest;
}


void initLibgcrypt()
{
    /* Version check should be the very first call because it
          makes sure that important subsystems are initialized. */
    if (!gcry_check_version (GCRYPT_VERSION))
    {
        fputs ("libgcrypt version mismatch\n", stderr);
        exit (2);
    }
     
     /* We don't want to see any warnings, e.g. because we have not yet
          parsed program options which might be used to suppress such
          warnings. */
    gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
     
       /* ... If required, other initialization goes here.  Note that the
          process might still be running with increased privileges and that
          the secure memory has not been initialized.  */
     
       /* Allocate a pool of 16k secure memory.  This make the secure memory
          available and also drops privileges where needed.  */
    gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
     
     /* It is now okay to let Libgcrypt complain when there was/is
          a problem with the secure memory. */
    gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
     
       /* ... If required, other initialization goes here.  */
     
       /* Tell Libgcrypt that initialization has completed. */
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
}


