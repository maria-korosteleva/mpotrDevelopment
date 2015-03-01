#include <stdio.h>
#include <stdlib.h>
#include "b64.h"
#include <gcrypt.h>

void myprint(void);
void initLibgcrypt();
unsigned char* generateKeys();
unsigned char* getSomeNonce(int length);
unsigned char* hash(const unsigned char* str, int length);
unsigned char* exponent(const unsigned char* base, const unsigned char* power);
unsigned char* getPubPrivKey(char* b64_keys, const char* type);
unsigned char* xor (const unsigned char* left_64, const unsigned char* right_64);
unsigned char* minus(const unsigned char* first_64, const unsigned char* second_64);
unsigned char* mult(const unsigned char* first_64, const unsigned char* second_64);

void myprint()
{
    printf("hello world\n");
}


unsigned char* sign(const unsigned char* info, const unsigned char* key_64)
{
    int keyLen;
    unsigned char* key = unbase64(key_64, strlen(key_64), &keyLen);
    // 
    gcry_sexp_t key_s;
    int err = gcry_sexp_new (&key_s, key, keyLen, 0);
    if (err) {
        printf("gcrypt: failed to convert key to s-expression while signing\n");
        printf ("Failure: %s/%s\n",
                    gcry_strsource (err),
                    gcry_strerror (err));
    }
    // prepare data
    gcry_sexp_t data;
    unsigned char* info_h_64 = hash(info, strlen(info));
    int infoLen;
    unsigned char* info_hashed = unbase64(info_h_64, strlen(info_h_64), &infoLen);
    ///// 2nd variant
    //err = gcry_sexp_build (&data, NULL,
    //                    "(data (flags pkcs1)(hash %s %b))",
    //                    "sha256", (int)infoLen, info_hashed); 
    ///// 3d variant
    //err = gcry_sexp_build (&data, NULL,
    //                   "(data (flags pkcs1)(hash sha256 %b))",
    //                     (int)infoLen, info_hashed); 
    ///// 4th variant
    //err = gcry_sexp_build(&data, NULL, "%m", info_hashed)
    /////// First variant
    //unsigned char* param;
    //param = (unsigned char*) malloc ((strlen(info) + 40) * sizeof(char));
    //param[0] = '\0';
    //strcpy(param, "(data (flags pkcs1) (hash sha256 ");
    //strcat(param, info);
    //strcat(param, "))");
    //printf("Data prepared %s\n", param);
    //err = gcry_sexp_new (&data, param, strlen(param), 0); // Or build?
    gcry_mpi_t info_mpi;
    size_t info_mpi_len;
    err = gcry_mpi_scan(&info_mpi, GCRYMPI_FMT_USG, info_hashed, infoLen-1, &info_mpi_len);
    if (err) {
        printf("gcrypt: failed to scan mpi from info while signing\n");
        printf ("Failure: %s/%s\n",
                    gcry_strsource (err),
                    gcry_strerror (err));
    }
    err = gcry_sexp_build(&data, NULL, "%m", info_mpi);
    if (err) {
        printf("gcrypt: failed to convert data info\n");
        printf ("Failure: %s/%s\n",
                    gcry_strsource (err),
                    gcry_strerror (err));
    }
    
    // sign
    gcry_sexp_t signature;
    err = gcry_pk_sign (&signature, data, key_s);
    if (err) {
        printf("gcrypt: failed to sign\n");
        printf ("Failure: %s/%s\n",
                    gcry_strsource (err),
                    gcry_strerror (err));
    	int len = gcry_sexp_sprint(data, GCRYSEXP_FMT_DEFAULT, NULL, 0);
    	unsigned char* tmp = (unsigned char*) malloc ((len) * sizeof(char));
    	int length = gcry_sexp_sprint(data, GCRYSEXP_FMT_DEFAULT, tmp, len);
    	tmp[length] = '\0';
	printf("Data S-exp is \n %s \nInfoLen is %lu\nInfo64Len = %lu\n", tmp, strlen(info_hashed), strlen(info_h_64));
    }
    // to string
    int len = gcry_sexp_sprint(signature, GCRYSEXP_FMT_DEFAULT, NULL, 0);
    unsigned char* result = (unsigned char*) malloc ((len) * sizeof(char));
    int length = gcry_sexp_sprint(signature, GCRYSEXP_FMT_DEFAULT, result, len);
    result[length] = '\0';
    
    // finish
    int res_len = 0;
    unsigned char* res_64 = base64(result, len, &res_len);
    gcry_sexp_release(signature);
    gcry_sexp_release(data);
    free(result);
    //free(param);
    return res_64;
}

unsigned char* mult(const unsigned char* first_64, const unsigned char* second_64)
{
    int firstLen, secondLen;
    unsigned char* first = unbase64(first_64, strlen(first_64), &firstLen);
    unsigned char* second = unbase64(second_64, strlen(second_64), &secondLen);
    
    gcry_mpi_t module = gcry_mpi_set_ui(NULL, 123456789);
    size_t nscanned = 0;
    int err;
    // convert numbers
    gcry_mpi_t first_mpi = gcry_mpi_new (8);
    err = gcry_mpi_scan(&first_mpi, GCRYMPI_FMT_USG, first, strlen(first), &nscanned);
    if (err) {
        printf("gcrypt: failed to scan the base number\n");
    }
    
    gcry_mpi_t second_mpi = gcry_mpi_new (8);
    err = gcry_mpi_scan(&second_mpi, GCRYMPI_FMT_USG, second, strlen(second), &nscanned);
    if (err) {
        printf("gcrypt: failed to scan the power number\n");
    }
    gcry_mpi_t res = gcry_mpi_new (8);
    
    ////////// CHANGE HERE ///////
    gcry_mpi_mul (res, first_mpi, second_mpi);
    unsigned char* result;
    size_t length = 0;
    err = gcry_mpi_aprint (GCRYMPI_FMT_USG, &result, &length, res);
    int res_64_len = 0;
    unsigned char* result_64 = base64(result, length, &res_64_len);
    
    free(result);
    gcry_mpi_release(first_mpi);
    gcry_mpi_release(second_mpi);
    gcry_mpi_release(module);
    gcry_mpi_release(res);
    free(first);
    free(second);
    
    return result_64;
}

unsigned char* minus(const unsigned char* first_64, const unsigned char* second_64)
{
    int firstLen, secondLen;
    unsigned char* first = unbase64(first_64, strlen(first_64), &firstLen);
    unsigned char* second = unbase64(second_64, strlen(second_64), &secondLen);
    
    gcry_mpi_t module = gcry_mpi_set_ui(NULL, 123456789);
    size_t nscanned = 0;
    int err;
    // convert numbers
    gcry_mpi_t first_mpi = gcry_mpi_new (8);
    err = gcry_mpi_scan(&first_mpi, GCRYMPI_FMT_USG, first, strlen(first), &nscanned);
    if (err) {
        printf("gcrypt: failed to scan the base number\n");
    }
    
    gcry_mpi_t second_mpi = gcry_mpi_new (8);
    err = gcry_mpi_scan(&second_mpi, GCRYMPI_FMT_USG, second, strlen(second), &nscanned);
    if (err) {
        printf("gcrypt: failed to scan the power number\n");
    }
    gcry_mpi_t res = gcry_mpi_new (8);
    
    ////////// CHANGE HERE ///////
    gcry_mpi_sub (res, first_mpi, second_mpi);
    unsigned char* result;
    size_t length = 0;
    err = gcry_mpi_aprint (GCRYMPI_FMT_USG, &result, &length, res);
    // result = (char*) realloc (result, length+1);
    // result[length] = '\0';
    int res_64_len = 0;
    unsigned char* result_64 = base64(result, length, &res_64_len);
    
    free(result);
    gcry_mpi_release(first_mpi);
    gcry_mpi_release(second_mpi);
    gcry_mpi_release(module);
    gcry_mpi_release(res);
    free(first);
    free(second);
    
    return result_64;
}

unsigned char* xor (const unsigned char* left_64, const unsigned char* right_64)
{
    int leftLen, rightLen;
    unsigned char* left = unbase64(left_64, strlen(left_64), &leftLen);
    unsigned char* right = unbase64(right_64, strlen(right_64), &rightLen);
    // leftLen = strlen(left_64);
    // rightLen = strlen(right_64);
    
    int len = (leftLen > rightLen) ? rightLen : leftLen;
    if (leftLen != rightLen)
    {
        //printf("Crypto module warning: xor parameters have"
        //" different lengths. Proceed with fingers crossed\n");
        // "left %s, %d; right %s, %d; total %d\n", left_64, leftLen, right_64, rightLen, len);
    }
    unsigned char* result = (unsigned char*) malloc(len * sizeof(char));
    int i;
    for (i = 0; i < len; ++i)
    {
        result[i] = left[i] ^ right[i];
    }
  
    int res_64_len = 0;
    unsigned char* res_64 = base64(result, len, &res_64_len);  
    free(left);
    free(right);
    free(result);
    return res_64;
}


unsigned char* exponent(const unsigned char* base_64, const unsigned char* power_64)
{
    gcry_mpi_t module = gcry_mpi_set_ui(NULL, 123456789);
    size_t nscanned = 0;
    int err, baseLen = 0;
    unsigned char* base = 0; // raw
    // convert numbers
    gcry_mpi_t base_mpi = gcry_mpi_new (8);
    if ((base_64[0] == '2') && (strlen(base_64) == 1)){
        base_mpi = gcry_mpi_set_ui(base_mpi, 2);
    }
    else{ 
        base = unbase64(base_64, strlen(base_64), &baseLen);
        err = gcry_mpi_scan(&base_mpi, GCRYMPI_FMT_USG, base, baseLen, &nscanned);
        if (err) {
            printf("gcrypt: failed to scan the base number\n");
        }
    }
    
    int powerLen = 0;
    unsigned char* power = unbase64(power_64, strlen(power_64), &powerLen);
    
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
    // result = (char*) realloc (result, length+1);
    // result[length] = '\0';
    int res_64_len = 0;
    unsigned char* result_64 = base64(result, length, &res_64_len);
    
    if (base) free(base);
    free(result);
    gcry_mpi_release(power_mpi);
    gcry_mpi_release(base_mpi);
    gcry_mpi_release(module);
    gcry_mpi_release(res);
    
    return result_64;
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
    int res_len = 0;
    unsigned char* buffer_64 = base64(buffer, length, &res_len);
    free(buffer);
    return buffer_64;
}


unsigned char* hash(const unsigned char* str, int length)
{
    // int strLen = 0;
    // unsigned char* str = unbase64(str_64, strlen(str_64), &keysLen);
    int hash_len = gcry_md_get_algo_dlen(GCRY_MD_SHA256);
    //printf("SHA256 length is %d\n", hash_len);
    unsigned char* digest = (unsigned char*) gcry_malloc(hash_len+1);
    digest[hash_len] = '\0';
    gcry_md_hash_buffer(GCRY_MD_SHA256, digest, str, length);
    //printf("SHA256 digest is %s\nLegth is %lu\n", digest, strlen(digest));
    int res_len = 0;
    unsigned char* digest_64 = base64(digest, hash_len+1, &res_len);
    //printf("base64 digest is %s\nLegth is %lu\n", digest_64, strlen(digest_64));
    free(digest);
    return digest_64;
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


