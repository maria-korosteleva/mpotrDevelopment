#include <stdio.h>
#include <stdlib.h>
#include "b64.h"
#include <gcrypt.h>

// Some constants -- predefined prime numbers used in the protocol for modulo operations

//const int p_len = 2;
//const int q_len = 1;
const int p_len = 192;
const int q_len = 192;

const char p_64[] = "MAgCAwC/MwIBAg==";
const char p[] = ""
//    "\x01\xDF"; // 479 -- for debug
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
//    "\xEF"; // 239 -- for debug
    "\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xE4\x87\xED\x51\x10\xB4\x61\x1A\x62\x63\x31\x45\xC0\x6E\x0E\x68"
    "\x94\x81\x27\x04\x45\x33\xE6\x3A\x01\x05\xDF\x53\x1D\x89\xCD\x91\x28\xA5\x04\x3C\xC7\x1A\x02\x6E"
    "\xF7\xCA\x8C\xD9\xE6\x9D\x21\x8D\x98\x15\x85\x36\xF9\x2F\x8A\x1B\xA7\xF0\x9A\xB6\xB6\xA8\xE1\x22"
    "\xF2\x42\xDA\xBB\x31\x2F\x3F\x63\x7A\x26\x21\x74\xD3\x1B\xF6\xB5\x85\xFF\xAE\x5B\x7A\x03\x5B\xF6"
    "\xF7\x1C\x35\xFD\xAD\x44\xCF\xD2\xD7\x4F\x92\x08\xBE\x25\x8F\xF3\x24\x94\x33\x28\xF6\x72\x2D\x9E"
    "\xE1\x00\x3E\x5C\x50\xB1\xDF\x82\xCC\x6D\x24\x1B\x0E\x2A\xE9\xCD\x34\x8B\x1F\xD4\x7E\x92\x67\xAF"
    "\xC1\xB2\xAE\x91\xEE\x51\xD6\xCB\x0E\x31\x79\xAB\x10\x42\xA9\x5D\xCF\x6A\x94\x83\xB8\x4B\x4B\x36"
    "\xB3\x86\x1A\xA7\x25\x5E\x4C\x02\x78\xBA\x36\x04\x65\x11\xB9\x93\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";

// main functionality
void initLibgcrypt();
unsigned char* generateKeys();
unsigned char* getSomeNonce(int length);
unsigned char* hash(const unsigned char* str, int length);
unsigned char* exponent(const unsigned char* base, const unsigned char* power);
unsigned char* getPubPrivKey(const char* b64_keys, const char* type);
unsigned char* xor (const unsigned char* left_64, const unsigned char* right_64);
unsigned char* minus(const unsigned char* first_64, const unsigned char* second_64);
unsigned char* mult(const unsigned char* first_64, const unsigned char* second_64, char state);
unsigned char* sign(const unsigned char* info, const unsigned char* key_64);
int verifySign(const unsigned char* info, const unsigned char* sign_64, const unsigned char* pubKey_64);
// Additional functions
void myprint(void);
void expCheck();
void round4Check();
void findq(void);

void myprint()
{
    printf("hello world\n");
}

// Check Auth part of the IDSKE proto
// that is  g^r_i mod p == (g^(r_i - c_i*x_i mod q) mod p) * ((g^x_i mod p) ^ c_i mod p) mod p
// when g is a generator (mod p), p is prime and q == (p-1)/2 is prime
// This checker can help to determine whether or not the whole process is correct
void round4Check()
{
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
    gcry_mpi_t q_mpi;
    size_t q_mpi_len;
    err = gcry_mpi_scan(&q_mpi, GCRYMPI_FMT_USG, q, q_len, &q_mpi_len);
    if (err) {
        printf("gcrypt: failed to scan mpi from q prime number\n");
        printf ("Failure: %s/%s\n",
                    gcry_strsource (err),
                    gcry_strerror (err));
    } 
    
    //p_mpi = gcry_mpi_set_ui(NULL, 439);

    gcry_mpi_t mpi_g = gcry_mpi_set_ui(NULL, 2); 
    gcry_mpi_t mpi_x_i = gcry_mpi_set_ui(NULL, 237); 
    gcry_mpi_t mpi_c_i = gcry_mpi_set_ui(NULL, 235); 
    gcry_mpi_t mpi_r_i = gcry_mpi_set_ui(NULL, 234); 
   
    // left part of the property
    gcry_mpi_t mpi_exp_1 = gcry_mpi_new(8);
    gcry_mpi_powm(mpi_exp_1, mpi_g, mpi_r_i, p_mpi); 
    
    // that is  g^r_i mod p == (g^(r_i - c_i*x_i mod q) mod p) * ((g^x_i mod p) ^ c_i mod p) mod p
    // right part of the property
    gcry_mpi_t mpi_exp_2 = gcry_mpi_new(8);
    gcry_mpi_mulm(mpi_exp_2, mpi_c_i, mpi_x_i, q_mpi); // q must be placed here
    gcry_mpi_subm(mpi_exp_2, mpi_r_i, mpi_exp_2, q_mpi);
    gcry_mpi_powm(mpi_exp_2, mpi_g, mpi_exp_2, p_mpi); 
    
    gcry_mpi_t mpi_exp_2_2 = gcry_mpi_new(8);
    gcry_mpi_powm(mpi_exp_2_2, mpi_g, mpi_x_i, p_mpi); 
    gcry_mpi_powm(mpi_exp_2_2, mpi_exp_2_2, mpi_c_i, p_mpi);

    gcry_mpi_mulm(mpi_exp_2, mpi_exp_2, mpi_exp_2_2, p_mpi); 
    
    // compare left and right parts
    gcry_mpi_t mpi_res = gcry_mpi_new(8);
    gcry_mpi_sub(mpi_res, mpi_exp_1, mpi_exp_2);
    //gcry_mpi_mod(mpi_res, mpi_res, p_mpi);
    
    gcry_mpi_aprint(GCRYMPI_FMT_HEX, &result, &reslen, mpi_res);
    printf("This is the result of comparising for Round4 (should be 0) %lu :\n%s\n\n", reslen, result);
    
    free(result);
    gcry_mpi_release(p_mpi); 
    gcry_mpi_release(q_mpi); 
    gcry_mpi_release(mpi_exp_1); 
    gcry_mpi_release(mpi_exp_2);
    gcry_mpi_release(mpi_exp_2_2);
    gcry_mpi_release(mpi_res);
    gcry_mpi_release(mpi_g);
    gcry_mpi_release(mpi_x_i);
    gcry_mpi_release(mpi_c_i);
    gcry_mpi_release(mpi_r_i);
}

// Check the exponent's property that (g^a mod p)^b mod p == (g^b mod p)^a mod p
// when g is a generator (mod p), p is prime and (p-1)/2 is prime
// This checker can help to determine whether or not the chosen prime p is correct
void expCheck()
{
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
    
    //p_mpi = gcry_mpi_set_ui(NULL, 439);

    gcry_mpi_t mpi_g = gcry_mpi_set_ui(NULL, 2); 
    gcry_mpi_t mpi_a = gcry_mpi_set_ui(NULL, 238); 
    gcry_mpi_t mpi_b = gcry_mpi_set_ui(NULL, 237); 
   
    // left part of the property
    gcry_mpi_t mpi_exp_1 = gcry_mpi_new(8);
    gcry_mpi_powm(mpi_exp_1, mpi_g, mpi_a, p_mpi); 
    gcry_mpi_powm(mpi_exp_1, mpi_exp_1, mpi_b, p_mpi); 
    
    // right part of the property
    gcry_mpi_t mpi_exp_2 = gcry_mpi_new(8);
    gcry_mpi_powm(mpi_exp_2, mpi_g, mpi_b, p_mpi); 
    gcry_mpi_powm(mpi_exp_2, mpi_exp_2, mpi_a, p_mpi); 
    
    // compare left and right parts
    gcry_mpi_t mpi_res = gcry_mpi_new(8);
    gcry_mpi_sub(mpi_res, mpi_exp_1, mpi_exp_2);
    //gcry_mpi_mod(mpi_res, mpi_res, p_mpi);
    
    gcry_mpi_aprint(GCRYMPI_FMT_HEX, &result, &reslen, mpi_res);
    printf("This is the result of comparising (should be 0) %lu :\n%s\n\n", reslen, result);
    free(result);
    
    gcry_mpi_release(p_mpi); 
    gcry_mpi_release(mpi_exp_1); 
    gcry_mpi_release(mpi_exp_2);
    gcry_mpi_release(mpi_res);
}

// Deliver the q value from the p_64 value stated above
void findq()
{
    // MPI from p, 1, 2
    int p_tmp_len;
    unsigned char* p_tmp = unbase64(p_64, strlen(p_64), &p_tmp_len);
    unsigned char* result, *res1, *res2;
    size_t reslen, res1len, res2len;
    gcry_mpi_t p_mpi;
    size_t p_mpi_len;
    int err = gcry_mpi_scan(&p_mpi, GCRYMPI_FMT_USG, p_tmp, p_tmp_len, &p_mpi_len);
    free(p_tmp);
    if (err) {
        printf("gcrypt: failed to scan mpi from p prime number\n");
        printf ("Failure: %s/%s\n",
                    gcry_strsource (err),
                    gcry_strerror (err));
    } 
    gcry_mpi_aprint(GCRYMPI_FMT_HEX, &result, &reslen, p_mpi);
    printf("This should be a number ""p"" of length %lu and mpi length %lu :\n%s\n\n", reslen, p_mpi_len, result);
    free(result);
    
    gcry_mpi_t mpi_1 = gcry_mpi_set_ui(NULL, 1); 
    gcry_mpi_t mpi_2 = gcry_mpi_set_ui(NULL, 2); 
    
    // minus 1
    gcry_mpi_sub(p_mpi, p_mpi, mpi_1);
    gcry_mpi_aprint(GCRYMPI_FMT_HEX, &result, &reslen, p_mpi);
    printf("This should be a number ""p-1"" of length %lu :\n%s\n\n", reslen, result);
    free(result);
    
    // divide by 2
    gcry_mpi_div(p_mpi, mpi_1, p_mpi, mpi_2, 0);
    
    // back to char
    gcry_mpi_aprint(GCRYMPI_FMT_HEX, &result, &reslen, p_mpi);
    gcry_mpi_aprint(GCRYMPI_FMT_HEX, &res1, &res1len, mpi_1);
    
    // printf in appropriate manner
    printf("The resulting number is of length %lu:\n%s\n\n", reslen, result);
    
    // do the same for the reminder
    printf("The reminder is of legth %lu:\n%s\n\n", res1len, res1);
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
        printf("gcrypt: failed to scan mpi from q prime number\n");
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

// returns 0 if ok, otherwise returns non-zero (-1)
int verifySign(const unsigned char* info, const unsigned char* sign_64, const unsigned char* pubKey_64)
{
    int pubKeyLen, sigLen;
    unsigned char* pubKey = unbase64(pubKey_64, strlen(pubKey_64), &pubKeyLen);
    unsigned char* sign = unbase64(sign_64, strlen(sign_64), &sigLen);
    // 
    gcry_sexp_t key_s, sign_s;
    int err = gcry_sexp_new (&key_s, pubKey, pubKeyLen, 0);
    if (err) {
        printf("gcrypt: failed to convert pubKey to s-expression while verifying signature\n");
        printf ("Failure: %s/%s\n",
                    gcry_strsource (err),
                    gcry_strerror (err));
    }
    err = gcry_sexp_new (&sign_s, sign, sigLen, 0);
    if (err) {
        printf("gcrypt: failed to convert signature to s-expression while verifying signature\n");
        printf ("Failure: %s/%s\n",
                    gcry_strsource (err),
                    gcry_strerror (err));
    }
    // prepare data
    gcry_sexp_t data;
    unsigned char* info_h_64 = hash(info, strlen(info)); // we hope that info is a valid c-string
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
    
    // verify signature
    err = gcry_pk_verify(sign_s, data, key_s);
    // finalizing 
    gcry_sexp_release(sign_s);
    gcry_sexp_release(key_s);
    gcry_sexp_release(data);
    gcry_mpi_release(info_mpi);
    free(pubKey);
    free(sign);
    free(info_h_64);
    free(info_hashed);
    if (err) {
    	// signature is not valid
        //printf("gcrypt: failed to sign\n");
        printf ("Failure: %s/%s\n",
                    gcry_strsource (err),
                    gcry_strerror (err));
        return -1;
        //int len = gcry_sexp_sprint(data, GCRYSEXP_FMT_DEFAULT, NULL, 0);
        //unsigned char* tmp = (unsigned char*) malloc ((len) * sizeof(char));
        //int length = gcry_sexp_sprint(data, GCRYSEXP_FMT_DEFAULT, tmp, len);
        //tmp[length] = '\0';
        //printf("Data S-exp is \n %s \nInfoLen is %lu\nInfo64Len = %lu\n", tmp, strlen(info_hashed), strlen(info_h_64));
    }
    return 0;
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
    unsigned char* info_h_64 = hash(info, strlen(info)); // we hope that info is a valid c-string
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

// if state is 'q' we use the q number for modulo, if 'p' -- p number
// no other options
// Function returns NULL in case of wrong parameters
unsigned char* mult(const unsigned char* first_64, const unsigned char* second_64, char state)
{
    int firstLen, secondLen;
    unsigned char* first = unbase64(first_64, strlen(first_64), &firstLen);
    unsigned char* second = unbase64(second_64, strlen(second_64), &secondLen);
    
    //gcry_mpi_t module = gcry_mpi_set_ui(NULL, 123456789);
    gcry_mpi_t module; // This is the new module
    size_t module_len;
    if (state == 'q')
    {
        int err = gcry_mpi_scan(&module, GCRYMPI_FMT_USG, q, q_len, &module_len);
        if (err) {
            printf("gcrypt: failed to scan mpi from q prime number\n");
            printf ("Failure: %s/%s\n",
                        gcry_strsource (err),
                        gcry_strerror (err));
        } 
    }
    else if (state == 'p')
    {
        int err = gcry_mpi_scan(&module, GCRYMPI_FMT_USG, p, p_len, &module_len);
        if (err) {
            printf("gcrypt: failed to scan mpi from p prime number\n");
            printf ("Failure: %s/%s\n",
                        gcry_strsource (err),
                        gcry_strerror (err));
        } 
    }
    else 
    {
    	printf("Error: wrong parameter of mult function\n");
	return NULL;
    }
    size_t nscanned = 0;
    // convert numbers
    gcry_mpi_t first_mpi = gcry_mpi_new (8);
    int err = gcry_mpi_scan(&first_mpi, GCRYMPI_FMT_USG, first, firstLen, &nscanned);
    if (err) {
        printf("gcrypt: failed to scan the first number in mult\n");
    }
    
    gcry_mpi_t second_mpi = gcry_mpi_new (8);
    err = gcry_mpi_scan(&second_mpi, GCRYMPI_FMT_USG, second, secondLen, &nscanned);
    if (err) {
        printf("gcrypt: failed to scan the second number in mult\n");
    }
    gcry_mpi_t res = gcry_mpi_new (8);
    
    /////
    gcry_mpi_mulm (res, first_mpi, second_mpi, module);
    /////

    unsigned char* result;
    size_t length = 0;
    /*
    err = gcry_mpi_aprint (GCRYMPI_FMT_HEX, &first1, &length, first_mpi);
    err = gcry_mpi_aprint (GCRYMPI_FMT_HEX, &second1, &length, second_mpi);
    err = gcry_mpi_aprint (GCRYMPI_FMT_HEX, &result, &length, res);
    printf("Result of %s mult %s is %s\n", first1, second1, result);
    free(result);
    free(first1);
    free(second1);
    */
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
    
    //gcry_mpi_t module = gcry_mpi_set_ui(NULL, 123456789);
    gcry_mpi_t q_mpi; // This is the new module
    size_t q_mpi_len;
    int err = gcry_mpi_scan(&q_mpi, GCRYMPI_FMT_USG, q, q_len, &q_mpi_len);
    if (err) {
        printf("gcrypt: failed to scan mpi from p prime number\n");
        printf ("Failure: %s/%s\n",
                    gcry_strsource (err),
                    gcry_strerror (err));
    } 
    size_t nscanned = 0;
    // convert numbers
    gcry_mpi_t first_mpi = gcry_mpi_new (8);
    err = gcry_mpi_scan(&first_mpi, GCRYMPI_FMT_USG, first, firstLen, &nscanned);
    if (err) {
        printf("gcrypt: failed to scan the first number in minus\n");
    }
    
    gcry_mpi_t second_mpi = gcry_mpi_new (8);
    err = gcry_mpi_scan(&second_mpi, GCRYMPI_FMT_USG, second, secondLen, &nscanned);
    if (err) {
        printf("gcrypt: failed to scan the second number in minus\n");
    }
    gcry_mpi_t res = gcry_mpi_new (8);
    
    /////
    gcry_mpi_subm (res, first_mpi, second_mpi, q_mpi);
    /////
    
    unsigned char* result;
    size_t length = 0;
    /*
    err = gcry_mpi_aprint (GCRYMPI_FMT_HEX, &first1, &length, first_mpi);
    err = gcry_mpi_aprint (GCRYMPI_FMT_HEX, &second1, &length, second_mpi);
    err = gcry_mpi_aprint (GCRYMPI_FMT_HEX, &result, &length, res);
    printf("Result of %s minus %s is %s\n", first1, second1, result);
    free(result);
    free(first1);
    free(second1);
    */
    err = gcry_mpi_aprint (GCRYMPI_FMT_USG, &result, &length, res);
    // result = (char*) realloc (result, length+1);
    // result[length] = '\0';
    int res_64_len = 0;
    unsigned char* result_64 = base64(result, length, &res_64_len);
    
    free(result);
    gcry_mpi_release(first_mpi);
    gcry_mpi_release(second_mpi);
    gcry_mpi_release(q_mpi);
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
    //gcry_mpi_t module = gcry_mpi_set_ui(NULL, 123456789);
    gcry_mpi_t p_mpi; // This is the new module
    size_t p_mpi_len;
    int err = gcry_mpi_scan(&p_mpi, GCRYMPI_FMT_USG, p, p_len, &p_mpi_len);
    if (err) {
        printf("gcrypt: failed to scan mpi from p prime number\n");
        printf ("Failure: %s/%s\n",
                    gcry_strsource (err),
                    gcry_strerror (err));
    } 
    
    size_t nscanned = 0;
    int baseLen = 0;
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
            printf ("Failure: %s/%s\n",
                    gcry_strsource (err),
                    gcry_strerror (err));
        }
    }
    
    int powerLen = 0;
    unsigned char* power = unbase64(power_64, strlen(power_64), &powerLen);
    
    gcry_mpi_t power_mpi = gcry_mpi_new (8);
    err = gcry_mpi_scan(&power_mpi, GCRYMPI_FMT_USG, power, powerLen, &nscanned);
    if (err) {
        printf("gcrypt: failed to scan the power number\n");
        printf ("Failure: %s/%s\n",
                    gcry_strsource (err),
                    gcry_strerror (err));
    }
    gcry_mpi_t res = gcry_mpi_new (8);
    
    ////
    gcry_mpi_powm(res, base_mpi, power_mpi, p_mpi);
    ////
    
    unsigned char* result;
    size_t length = 0;
    /*
    err = gcry_mpi_aprint (GCRYMPI_FMT_HEX, &base1, &length, base_mpi);
    err = gcry_mpi_aprint (GCRYMPI_FMT_HEX, &power1, &length, power_mpi);
    err = gcry_mpi_aprint (GCRYMPI_FMT_HEX, &result, &length, res);
    printf("Result of power %s to %s is %s\n", base1, power1, result);
    free(result);
    free(base1);
    free(power1);
    */
    err = gcry_mpi_aprint (GCRYMPI_FMT_USG, &result, &length, res);
    if (err) {
        printf("gcrypt: failed to print the result, exponent\n");
        printf ("Failure: %s/%s\n",
                    gcry_strsource (err),
                    gcry_strerror (err));
    }
    // result = (char*) realloc (result, length+1);
    // result[length] = '\0';
    int res_64_len = 0;
    unsigned char* result_64 = base64(result, length, &res_64_len);
    /*
    printf("Length of raw result in exp is %lu, of base64 is %d\n", length, res_64_len);
    */
    if (base) free(base);
    free(power);
    free(result);
    gcry_mpi_release(power_mpi);
    gcry_mpi_release(base_mpi);
    gcry_mpi_release(p_mpi);
    gcry_mpi_release(res);
    
    return result_64;
}

unsigned char* getPubPrivKey(const char* b64_keys, const char* type)
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
    free(keys);
    
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

// if length == 0 then the randomization is made modulo q
unsigned char* getSomeNonce(int length)
{
    //printf("getNonce of length %d\n", length);
    if (!length) length = q_len; // not for everyone, at least not for k values
    
    //unsigned char* buffer;
    unsigned char* buffer = (unsigned char*) gcry_malloc(length * sizeof(char));
    //unsigned char* buffer = (unsigned char*) gcry_malloc((length+1) * sizeof(char));
    //buffer[length] = '\0';
    // randomize
    //gcry_randomize (buffer, length, GCRY_STRONG_RANDOM);
    //size_t buflen = length;
    //unsigned char* buffer = gcry_random_bytes (length, GCRY_STRONG_RANDOM);
    gcry_create_nonce(buffer, length);

    if (length == q_len)
    {
    	//printf("Non-k generation\n");
        gcry_mpi_t q_mpi, buf_mpi;
        size_t q_mpi_len, buf_mpi_len;
        int err = gcry_mpi_scan(&q_mpi, GCRYMPI_FMT_USG, q, q_len, &q_mpi_len);
        if (err) {
            printf("gcrypt: failed to scan mpi from q prime number in GetSome nonce\n");
            printf ("Failure: %s/%s\n",
                        gcry_strsource (err),
                        gcry_strerror (err));
        } 
        err = gcry_mpi_scan(&buf_mpi, GCRYMPI_FMT_USG, buffer, length, &buf_mpi_len);
        if (err) {
            printf("gcrypt: failed to scan mpi from buffer in GetSomeNonce\n");
            printf ("Failure: %s/%s\n",
                        gcry_strsource (err),
                        gcry_strerror (err));
        } 
	////
	//gcry_mpi_t tmp_res_mpi = gcry_mpi_new(8);
	//gcry_mpi_sub(tmp_res_mpi, q_mpi, buf_mpi);
	//unsigned char* tmp_res;
	//size_t tmp_res_len;
	//gcry_mpi_aprint(GCRYMPI_FMT_HEX, &tmp_res, &tmp_res_len, tmp_res_mpi);
	//printf("Subb q - buffer is \n%s\n", tmp_res);
	//free(tmp_res);
	//gcry_mpi_release(tmp_res_mpi);
        ////
        gcry_mpi_mod(buf_mpi, buf_mpi, q_mpi);
        size_t res_buf_len;
	free(buffer);
        //gcry_mpi_aprint(GCRYMPI_FMT_HEX, &buffer, &res_buf_len, buf_mpi);
	//printf("Generation res is %s\n", buffer);
	//free(buffer);
        gcry_mpi_aprint(GCRYMPI_FMT_USG, &buffer, &res_buf_len, buf_mpi);
	length = res_buf_len;
	// if length is not enough?? 
        gcry_mpi_release(q_mpi);
        gcry_mpi_release(buf_mpi);
    }
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


