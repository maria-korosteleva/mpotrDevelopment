#include <stdio.h>
#include <stdlib.h>
#include "b64.h"
#include <gcrypt.h>

void myprint(void);
void initLibgcrypt();
unsigned char* generateKeys();
unsigned char* getSomeNonce(int length);
unsigned char* hash(unsigned char* str, int length);
unsigned char* exponent(const unsigned char* base, const unsigned char* power);
unsigned char* getPubPrivKey(char* b64_keys, const char* type);

void myprint()
{
    printf("hello world\n");
}

unsigned char* exponent(const unsigned char* base, const unsigned char* power)
{
    gcry_mpi_t module = gcry_mpi_set_ui(NULL, 123456789);
    size_t nscanned = 0;
    int err;
    // convert numbers
    gcry_mpi_t base_mpi = gcry_mpi_new (8);
    if ((base[0] == '2') && (strlen(base) == 1)){
        base_mpi = gcry_mpi_set_ui(base_mpi, 2);
    }
    else{ 
        err = gcry_mpi_scan(&base_mpi, GCRYMPI_FMT_USG, base, strlen(base), &nscanned);
        if (err) {
            printf("gcrypt: failed to scan the base number\n");
        }
    }
    gcry_mpi_t power_mpi = gcry_mpi_new (8);
    err = gcry_mpi_scan(&power_mpi, GCRYMPI_FMT_USG, power, strlen(power), &nscanned);
    if (err) {
        printf("gcrypt: failed to scan the power number\n");
    }
    gcry_mpi_t res = gcry_mpi_new (8);
    gcry_mpi_powm(res, base_mpi, power_mpi, module);
    unsigned char* result;
    size_t length = 0;
    err = gcry_mpi_aprint (GCRYMPI_FMT_USG, &result, &length, res);
    result = (char*) realloc (result, length+1);
    result[length] = '\0';
    
    gcry_mpi_release(power_mpi);
    gcry_mpi_release(base_mpi);
    gcry_mpi_release(module);
    gcry_mpi_release(res);
    
    return result;
}

unsigned char* getPubPrivKey(char* b64_keys, const char* type)
{
    int keysLen = 0;
    unsigned char* keys = unbase64(b64_keys, strlen(b64_keys), &keysLen);
    gcry_sexp_t r_key;
    int err = gcry_sexp_new (&r_key, keys, keysLen, 0);
    if (err) {
        printf("gcrypt: failed to convert key to s-expression\n");
    }
    gcry_sexp_t r_sub_key; // can conta
    r_sub_key = gcry_sexp_find_token(r_key, type, 0);
    if (r_sub_key == NULL){
        printf("gcrypt: failed to find sub key\n");
        printf ("Failure: %s/%s\n",
                    gcry_strsource (err),
                    gcry_strerror (err));
    }
    int len = gcry_sexp_sprint(r_sub_key, GCRYSEXP_FMT_DEFAULT, NULL, 0);
    unsigned char* sub_key = (unsigned char*) malloc ((len) * sizeof(char));
    int length = gcry_sexp_sprint(r_sub_key, GCRYSEXP_FMT_DEFAULT, sub_key, len);
    sub_key[length] = '\0';
       
    // make it base64
    int res_len = 0;
    unsigned char* buffer_res = base64(sub_key, len, &res_len);
    
    gcry_sexp_release(r_key);
    gcry_sexp_release(r_sub_key);
    free(sub_key);
    
    return buffer_res;
}

unsigned char* generateKeys()
{
    gcry_sexp_t r_key, param;
    gcry_error_t err = gcry_sexp_build (&param, NULL, "(genkey (rsa (nbits 3:256)))");
    if (err) {
        printf("gcrypt: failed to create rsa params\n");
    }
    err = gcry_pk_genkey (&r_key, param);
    if (err) {
        printf("gcrypt: failed to create rsa keypair\n");
    }
    
    // To string
    int len = gcry_sexp_sprint(r_key, GCRYSEXP_FMT_DEFAULT, NULL, 0);
    char* buffer = (char*) malloc ((len) * sizeof(char));
    int length = gcry_sexp_sprint(r_key, GCRYSEXP_FMT_DEFAULT, buffer, len);
    buffer[length] = '\0';
    
    // make it base64
    int res_len = 0;
    unsigned char* buffer_res = base64(buffer, len, &res_len);
    // printf("base64 result: %s\n", buffer_res);
    
    gcry_sexp_release(r_key);
    gcry_sexp_release(param);
    free(buffer);
    
    return buffer_res;
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


