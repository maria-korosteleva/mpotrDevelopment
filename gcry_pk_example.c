#include <gcrypt.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

int main (int argc, char **argv) {
   static const char message[] = "hello";
   GcrySexp gen_parms, sign_parms, keypair, pubkey, skey, sig;
   size_t errof=0;
   int rc;

   gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
   /* shortest key I could find */
   rc = gcry_sexp_build (&gen_parms, &errof, "(genkey (rsa (nbits 
3:256)))");
   assert(rc == 0);
   rc = gcry_pk_genkey(&keypair, gen_parms);
   assert(rc == 0);

   skey = gcry_sexp_find_token(keypair, "private-key", 0);
   pubkey = gcry_sexp_find_token(keypair, "public-key", 0);
   assert(skey != NULL);
   assert(pubkey != NULL);

   rc = gcry_sexp_build (&sign_parms, &errof,
                         "(data (flags) (value \"%s\"))\n", message);
   assert(rc == 0);

   rc = gcry_pk_sign (&sig, sign_parms, skey);
   assert(rc == 0);
   gcry_sexp_dump(sig);

   rc = gcry_pk_verify (sig, sign_parms, pubkey);
   if(rc != 0) {
     printf("verify returns error %d: %s\n", rc, gcry_strerror(rc));
   }

   exit(EXIT_SUCCESS);
}
