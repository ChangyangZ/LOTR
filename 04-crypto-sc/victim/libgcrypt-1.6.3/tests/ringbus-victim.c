/*
 * This is a simplified version of the pubkey.c unit test
 * that we will use as the victim calling the functions
 * of interest from the libgcrypt library.
 *
 * We run the victim from this test file because it's easier than writing a standalone C file.
 * The test function called above performs one signature of some fixed hashed data, with a "random" key.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../scutil/lotr.h"

#include "../src/gcrypt-int.h"

#define my_isascii(c) (!((c) & 0x80))
#define digitp(p)   (*(p) >= '0' && *(p) <= '9')
#define hexdigitp(a) (digitp (a)                     \
                      || (*(a) >= 'A' && *(a) <= 'F')  \
                      || (*(a) >= 'a' && *(a) <= 'f'))
#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): \
                     *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))
#define DIM(v)		     (sizeof(v)/sizeof((v)[0]))
#define DIMof(type,member)   DIM(((type *)0)->member)

static int verbose;
static int error_count;

static void
die (const char *format, ...)
{
  va_list arg_ptr ;

  va_start( arg_ptr, format ) ;
  vfprintf (stderr, format, arg_ptr );
  va_end(arg_ptr);
  if (*format && format[strlen(format)-1] != '\n')
    putc ('\n', stderr);
  exit (1);
}

static void
fail (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  error_count++;
}

static void
info (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
}

static void
show_sexp (const char *prefix, gcry_sexp_t a)
{
  char *buf;
  size_t size;

  if (prefix)
    fputs (prefix, stderr);
  size = gcry_sexp_sprint (a, GCRYSEXP_FMT_ADVANCED, NULL, 0);
  buf = gcry_xmalloc (size);

  gcry_sexp_sprint (a, GCRYSEXP_FMT_ADVANCED, buf, size);
  fprintf (stderr, "%.*s", (int)size, buf);
  gcry_free (buf);
}


/* Convert STRING consisting of hex characters into its binary
   representation and return it as an allocated buffer. The valid
   length of the buffer is returned at R_LENGTH.  The string is
   delimited by end of string.  The function returns NULL on
   error.  */
static void *
data_from_hex (const char *string, size_t *r_length)
{
  const char *s;
  unsigned char *buffer;
  size_t length;

  buffer = gcry_xmalloc (strlen(string)/2+1);
  length = 0;
  for (s=string; *s; s +=2 )
    {
      if (!hexdigitp (s) || !hexdigitp (s+1))
        die ("error parsing hex string `%s'\n", string);
      ((unsigned char*)buffer)[length++] = xtoi_2 (s);
    }
  *r_length = length;
  return buffer;
}


static void
extract_cmp_data (gcry_sexp_t sexp, const char *name, const char *expected)
{
  gcry_sexp_t l1;
  const void *a;
  size_t alen;
  void *b;
  size_t blen;

  l1 = gcry_sexp_find_token (sexp, name, 0);
  a = gcry_sexp_nth_data (l1, 1, &alen);
  b = data_from_hex (expected, &blen);
  if (!a)
    fail ("parameter \"%s\" missing in key\n", name);
  else if ( alen != blen || memcmp (a, b, alen) )
    {
      fail ("parameter \"%s\" does not match expected value\n", name);
      if (verbose)
        {
          info ("expected: %s\n", expected);
          show_sexp ("sexp: ", sexp);
        }
    }
  gcry_free (b);
  gcry_sexp_release (l1);
}


static void
check_ed25519ecdsa_sample_key (void)
{
  u_int64_t randomval = 7;
  static char ecc_private_key_wo_q[4000];
  sprintf(ecc_private_key_wo_q,
    "(private-key\n"
    " (ecc\n"
    "  (curve \"Ed25519\")\n"
    "  (d #09A0C38E0F1699073541447C19DA12E3A07A7BFDB0C186E4%016lx#)"
    "))", randomval);

  static const char hash_string[] =
    "(data (flags rfc6979)\n"
    " (hash sha256 #00112233445566778899AABBCCDDEEFF"
    /* */          "000102030405060708090A0B0C0D0E0F#))";

  gpg_error_t err;
  gcry_sexp_t key, hash, sig;

  if (verbose)
    fprintf (stderr, "Checking sample Ed25519/ECDSA key.\n");

  /* Sign without a Q parameter.  */
  if ((err = gcry_sexp_new (&hash, hash_string, 0, 1)))
    die ("line %d: %s", __LINE__, gpg_strerror (err));
  if ((err = gcry_sexp_new (&key, ecc_private_key_wo_q, 0, 1)))
    die ("line %d: %s", __LINE__, gpg_strerror (err));

  /*********************************************************/
  // From here we basically provide an on-demand signing service
  // to the monitor by repeating the gcry_pk_sign operation

  pin_cpu(5);   // 5 for the full flush; 6 for the L1/L2 only

  volatile struct sharestruct *mysharestruct = get_sharestruct();
  mysharestruct->iteration_of_interest_running = 0;
  mysharestruct->sign_requested = 0;
  mysharestruct->cleansing_mechanism = 1;

  fprintf(stderr, "GO\n");

  while(1) {

    // If a sign was requested
    if (mysharestruct->sign_requested) {

      // Wait a moment for the attacker to get ready
      wait_cycles(10000);

      // Start vulnerable code
      if ((err = gcry_pk_sign (&sig, hash, key)))
        die ("gcry_pk_sign w/o Q failed: %s", gpg_strerror (err));
    }
  }

  /*********************************************************/

  gcry_sexp_release (sig);
  gcry_sexp_release (key);
  gcry_sexp_release (hash);
}

int
main (int argc, char **argv)
{
  int debug = 0;

  if (argc > 1 && !strcmp (argv[1], "--verbose"))
    verbose = 1;
  else if (argc > 1 && !strcmp (argv[1], "--debug"))
    {
      verbose = 2;
      debug = 1;
    }

  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  if (!gcry_check_version (GCRYPT_VERSION))
    die ("version mismatch\n");
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  if (debug)
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u , 0);
  /* No valuable keys are create, so we can speed up our RNG. */
  gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);

  check_ed25519ecdsa_sample_key ();

  return !!error_count;
}
