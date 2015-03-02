#include <stdio.h>
#include <stdlib.h>
#include "b64.h"
#include <gcrypt.h>

// Some constants -- predefined prime numbers used in the protocol for modulo operations
const int p_len = 192;
const int q_len = 192;

const char p[] = ""
    "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xC9\x0F\xDA\xA2\x21\x68\xC2\x34\xC4\xC6\x62\x8B\x80\xDC\x1C\xD1"
    "\x29\x02\x4E\x08\x8A\x67\xCC\x74\x02\x0B\xBE\xA6\x3B\x13\x9B\x22\x51\x4A\x08\x79\x8E\x34\x04\xDD"
    "\xEF\x95\x19\xB3\xCD\x3A\x43\x1B\x30\x2B\x0A\x6D\xF2\x5F\x14\x37\x4F\xE1\x35\x6D\x6D\x51\xC2\x45"
    "\xE4\x85\xB5\x76\x62\x5E\x7E\xC6\xF4\x4C\x42\xE9\xA6\x37\xED\x6B\x0B\xFF\x5C\xB6\xF4\x06\xB7\xED"
    "\xEE\x38\x6B\xFB\x5A\x89\x9F\xA5\xAE\x9F\x24\x11\x7C\x4B\x1F\xE6\x49\x28\x66\x51\xEC\xE4\x5B\x3D"
    "\xC2\x00\x7C\xB8\xA1\x63\xBF\x05\x98\xDA\x48\x36\x1C\x55\xD3\x9A\x69\x16\x3F\xA8\xFD\x24\xCF\x5F"
    "\x83\x65\x5D\x23\xDC\xA3\xAD\x96\x1C\x62\xF3\x56\x20\x85\x52\xBB\x9E\xD5\x29\x07\x70\x96\x96\x6D"
    "\x67\x0C\x35\x4E\x4A\xBC\x98\x04\xF1\x74\x6C\x08\xCA\x23\x73\x27\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
// p = 2*q +1
const char q[] = ""
    "\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xE4\x87\xED\x51\x10\xB4\x61\x1A\x62\x63\x31\x45\xC0\x6E\x0E\x68"
    "\x94\x81\x27\x04\x45\x33\xE6\x3A\x01\x05\xDF\x53\x1D\x89\xCD\x91\x28\xA5\x04\x3C\xC7\x1A\x02\x6E"
    "\xF7\xCA\x8C\xD9\xE6\x9D\x21\x8D\x98\x15\x85\x36\xF9\x2F\x8A\x1B\xA7\xF0\x9A\xB6\xB6\xA8\xE1\x22"
    "\xF2\x42\xDA\xBB\x31\x2F\x3F\x63\x7A\x26\x21\x74\xD3\x1B\xF6\xB5\x85\xFF\xAE\x5B\x7A\x03\x5B\xF6"
    "\xF7\x1C\x35\xFD\xAD\x44\xCF\xD2\xD7\x4F\x92\x08\xBE\x25\x8F\xF3\x24\x94\x33\x28\xF6\x72\x2D\x9E"
    "\xE1\x00\x3E\x5C\x50\xB1\xDF\x82\xCC\x6D\x24\x1B\x0E\x2A\xE9\xCD\x34\x8B\x1F\xD4\x7E\x92\x67\xAF"
    "\xC1\xB2\xAE\x91\xEE\x51\xD6\xCB\x0E\x31\x79\xAB\x10\x42\xA9\x5D\xCF\x6A\x94\x83\xB8\x4B\x4B\x36"
    "\xB3\x86\x1A\xA7\x25\x5E\x4C\x02\x78\xBA\x36\x04\x65\x11\xB9\x93\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";

void myprint(void);
void findq(void);
void initLibgcrypt();
unsigned char* generateKeys();
unsigned char* getSomeNonce(int length);
unsigned char* hash(const unsigned char* str, int length);
unsigned char* exponent(const unsigned char* base, const unsigned char* power);
unsigned char* getPubPrivKey(char* b64_keys, const char* type);
unsigned char* xor (const unsigned char* left_64, const unsigned char* right_64);
unsigned char* minus(const unsigned char* first_64, const unsigned char* second_64);
unsigned char* mult(const unsigned char* first_64, const unsigned char* second_64);
unsigned char* sign(const unsigned char* info, const unsigned char* key_64);

void myprint()
{
    printf("hello world\n");
}
// Deliver the q value from the p value stated above
void findq()
{
    // MPI from p, 1, 2
    unsigned char* result, *res1, *res2;
    size_t reslen, res1len, res2len;
    gcry_mpi_t p_mpi;
    size_t p_mpi_len;
    int err = gcry_mpi_scan(&p_mpi, GCRYMPI_FMT_USG, p, p_len, &p_mpi_len);
    if (err) {
        printf("gcrypt: failed to scan mpi from p prime number\n");
        printf ("Failure: %s/%s\n",
                    gcry_strsource (err),
                    gcry_strerror (err));
    } 
    gcry_mpi_aprint(GCRYMPI_FMT_HEX, &result, &reslen, p_mpi);
    printf("This should be a number ""p"" :\n%s\n\n", result);
    free(result);
    
    gcry_mpi_t mpi_1 = gcry_mpi_set_ui(NULL, 1); 
    gcry_mpi_t mpi_2 = gcry_mpi_set_ui(NULL, 2); 
    
    // minus 1
    gcry_mpi_sub(p_mpi, p_mpi, mpi_1);
    gcry_mpi_aprint(GCRYMPI_FMT_HEX, &result, &reslen, p_mpi);
    printf("This should be a number ""p-1"" :\n%s\n\n", result);
    free(result);
    
    // divide by 2
    gcry_mpi_div(p_mpi, mpi_1, p_mpi, mpi_2, 0);
    
    // back to char
    gcry_mpi_aprint(GCRYMPI_FMT_HEX, &result, &reslen, p_mpi);
    gcry_mpi_aprint(GCRYMPI_FMT_HEX, &res1, &res1len, mpi_1);
    
    // printf in appropriate manner
    printf("The resulting number is:\n%s\n\n", result);
    
    // do the same for the reminder
    printf("The reminder is:\n%s\n\n", res1);
    // Clean the area
    gcry_mpi_release(p_mpi); 
    gcry_mpi_release(mpi_1); 
    gcry_mpi_release(mpi_2);
/*  // Check if the value converted from q is ok
    // It is :)
    unsigned char* result;
    size_t reslen;
    gcry_mpi_t q_mpi;
    size_t q_mpi_len;
    int err = gcry_mpi_scan(&q_mpi, GCRYMPI_FMT_USG, q, q_len, &q_mpi_len);
    if (err) {
        printf("gcrypt: failed to scan mpi from p prime number\n");
        printf ("Failure: %s/%s\n",
                    gcry_strsource (err),
                    gcry_strerror (err));
    } 
    gcry_mpi_aprint(GCRYMPI_FMT_HEX, &result, &reslen, q_mpi);
    printf("This should be a number ""q"" :\n%s\n\n", result);
    free(result);
    gcry_mpi_release(q_mpi); 
*/
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
        //int len = gcry_sexp_sprint(data, GCRYSEXP_FMT_DEFAULT, NULL, 0);
        //unsigned char* tmp = (unsigned char*) malloc ((len) * sizeof(char));
        //int length = gcry_sexp_sprint(data, GCRYSEXP_FMT_DEFAULT, tmp, len);
        //tmp[length] = '\0';
        //printf("Data S-exp is \n %s \nInfoLen is %lu\nInfo64Len = %lu\n", tmp, strlen(info_hashed), strlen(info_h_64));
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
    gcry_sexp_release(key_s);
    gcry_sexp_release(data);
    gcry_mpi_release(info_mpi);
    free(result);
    free(key);
    free(info_h_64);
    free(info_hashed);
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


