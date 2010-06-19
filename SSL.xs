#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>

#define recvsize *((unsigned short *) bio->ptr)
#define sendsize *((unsigned short *) (bio->ptr+2))
#define BUFSIZE 32768

static int pfs_bio_create( BIO *bio ) {
#ifdef DEBUG
   printf("create!\n");
#endif
   bio->init = 1;
   bio->num = 0;
   bio->ptr = malloc((BUFSIZE * 2) + 4);
   memset(bio->ptr, 0, 4);
   bio->flags = 0;
   return 1;
}

static int pfs_bio_destroy( BIO *bio ) {
#ifdef DEBUG
   printf("pfs_bio_destroy!");
#endif
   if (bio->ptr != 0) {
#ifdef DEBUG
      printf("x");
#endif
      free(bio->ptr);
      bio->ptr = 0;
   }
#ifdef DEBUG
   printf("\n");
#endif
   return 1;
}

static int pfs_bio_read( BIO *bio, char *buf, int len ) {
   int mylen = len;
#ifdef DEBUG
   printf("pfs_bio_read! %d %d\n", len, bio->ptr);
#endif
   BIO_clear_retry_flags(bio);
   if ((bio != 0) && (bio->ptr != 0)) {
      if (mylen > recvsize) mylen = recvsize;
      memcpy(buf, (bio->ptr+4), mylen);
#ifdef DEBUG
      printf("pfs_bio_read2! %d %d\n", len, mylen);
      int i = 0;
      for(i = 0; i < mylen; i++) {
         printf("%02X:", *((unsigned char *) bio->ptr+4 + i));
      }
      printf("\n");
#endif
      memmove((bio->ptr+4), (bio->ptr+4 + mylen), (recvsize-mylen));
      recvsize -= mylen;
      BIO_clear_retry_flags( bio );
      return mylen;
   }
   return 0;
}

static int pfs_bio_write( BIO *bio, const char *buf, int len ) {
#ifdef DEBUG
   printf("pfs_bio_write! %d\n", len);
#endif
   if ((sendsize + len) > BUFSIZE) len = BUFSIZE - sendsize;
   memcpy(bio->ptr+4+BUFSIZE+sendsize, buf, len);
   sendsize += len;
   BIO_clear_retry_flags( bio );
   return len;
}

static long pfs_bio_ctrl( BIO *bio, int cmd, long num, void *ptr ) {
#ifdef DEBUG
   printf("pfs_bio_ctrl! %d ",  bio);
   if (cmd == BIO_CTRL_EOF) {
      printf("BIO_CTRL_EOF\n");
   } else if (cmd == BIO_CTRL_RESET) {
      printf("BIO_CTRL_RESET\n");
   } else if (cmd == BIO_C_FILE_SEEK) {
      printf("BIO_C_FILE_SEEK\n");
   } else if (cmd == BIO_C_FILE_TELL) {
      printf("BIO_C_FILE_TELL\n");
   } else if (cmd == BIO_CTRL_INFO) {
      printf("BIO_CTRL_INFO\n");
   } else if (cmd == BIO_CTRL_PENDING) {
      printf("BIO_CTRL_PENDING\n");
   } else if (cmd == BIO_CTRL_WPENDING) {
      printf("BIO_CTRL_WPENDING\n");
   } else if (cmd == BIO_CTRL_DUP) {
      printf("BIO_CTRL_DUP\n");
   } else if (cmd == BIO_CTRL_PUSH) {
      printf("BIO_CTRL_PUSH\n");
   } else if (cmd == BIO_CTRL_POP) {
      printf("BIO_CTRL_POP\n");
   } else
#endif
   if ( cmd == BIO_CTRL_FLUSH ) {
      /* The OpenSSL library needs this */
#ifdef DEBUG
      printf("BIO_CTRL_FLUSH\n");
#endif
      return 1;
#ifdef DEBUG
   } else {
      printf("%d\n", cmd);
#endif
   }
   return 0;
}

static int pfs_bio_gets( BIO *bio, char *buf, int len ) {
#ifdef DEBUG
   printf("pfs_bio_gets!\n");
#endif
   return -1;
}

static int pfs_bio_puts( BIO *bio, const char *str ) {
   //printf("pfs_bio_puts!\n");
   return pfs_bio_write( bio, str, strlen( str ) );
}
   
static BIO_METHOD pfs_bio_method = {
   ( 100 | 0x400 ),
   "POE::Filter::SSL",
   pfs_bio_write,
   pfs_bio_read,
   pfs_bio_puts,
   pfs_bio_gets,
   pfs_bio_ctrl,
   pfs_bio_create,
   pfs_bio_destroy
};

MODULE = POE::Filter::SSL      PACKAGE = POE::Filter::SSL

BIO_METHOD *
BIO_get_handler()
   CODE:
      RETVAL = &pfs_bio_method;
   OUTPUT:
      RETVAL

ASN1_INTEGER *
BIO_write(bio, str)
   BIO *                bio
   CODE:
   STRLEN len;
   if ((recvsize + len) > BUFSIZE) len = BUFSIZE - recvsize;
   unsigned char* mystr = SvPV( ST(1), len);
   if ((bio == 0) || (bio->ptr == 0)) {
#ifdef DEBUG
      printf("BAD BIO: %d %d\n", bio, len);
#endif
      return;
   }
#ifdef DEBUG
   printf("Write: %d %d %d\n", bio, bio->ptr, len);
#endif
   memcpy(bio->ptr+4+recvsize, mystr, len);
   recvsize += len;
   sv_setnv(ST(0), len);
#ifdef DEBUG
   int i;
   printf("SRC:\n");
   for(i = 0; i < len; i++) {
      //(unsigned char *) bio->ptr + recvsize + i) = ((unsigned char *)  mystr + i);
      printf("%02X:",  *((unsigned char *)  mystr + i));
   }
   printf("\n");
   printf("DST:\n");
   for(i = 0; i < recvsize; i++) {
      printf("%02X:", *((unsigned char *) bio->ptr + i));
   }
   printf("\n");
#endif

ASN1_INTEGER *
BIO_read(bio)
   BIO *                bio
   CODE:
#ifdef DEBUG
      printf("BIO_read\n");
#endif
      if ((bio != 0) && (bio->ptr != 0)) {
#ifdef DEBUG
         printf("BIO_read: %d %d %d\n", bio, bio->ptr, sendsize);
#endif
         if ((bio->ptr != 0) && (sendsize > 0)) {
            sv_setpvn(ST(0), (unsigned char *) bio->ptr+BUFSIZE+4, sendsize);
         } else {
            sv_setpvn(ST(0), "", 0);
         }
         sendsize = 0;
      } else {
         sv_setpvn(ST(0), "", 0);
      }

ASN1_INTEGER *
X509_get_serialNumber(cert)
   X509 *      cert
   CODE:
   RETVAL = X509_get_serialNumber(cert);
   ST(0) = sv_newmortal();   /* Undefined to start with */
   sv_setpvn( ST(0), RETVAL->data, RETVAL->length);

ASN1_INTEGER *
verify_serial_against_crl_file(crlfile, serial)
   CODE:
   X509_CRL *crl=NULL;
   X509_REVOKED *revoked;
   BIO *in=NULL;
   int n,i,retval = 0;
   STRLEN len, lenser;
   unsigned char* crlfile = SvPV( ST(0), len);
   unsigned char* serial  = SvPV( ST(1), lenser);
   ST(0) = sv_newmortal();   /* Undefined to start with */

   /* check peer cert against CRL */
   if (len <= 0) {
      sv_setpvn(ST(0), "CRL: No file name given!", 24);
      goto end;
   }

   in=BIO_new(BIO_s_file());
   if (in == NULL) {
      sv_setpvn(ST(0), "CRL: BIO err", 12);
      goto end;
   }

   if (BIO_read_filename(in, crlfile) <= 0) {
      sv_setpvn(ST(0), "CRL: cannot read CRL File", 25);
      goto end;
   }

   crl=PEM_read_bio_X509_CRL(in,NULL,NULL,NULL);
   if (crl == NULL) {
      sv_setpvn(ST(0), "CRL: cannot read from CRL File", 30);
      goto end;
   }

   n = sk_num(X509_CRL_get_REVOKED(crl));
   if (n > 0) {
      for (i = 0; i < n; i++) {
         revoked = (X509_REVOKED *)sk_value(X509_CRL_get_REVOKED(crl), i);
         if ( (revoked->serialNumber->length > 0) &&
              (revoked->serialNumber->length == lenser) &&
              (strncmp(revoked->serialNumber->data, serial, lenser) == 0)) {
            sv_setpvn( ST(0), revoked->serialNumber->data, revoked->serialNumber->length);
            goto end;
         }
      }
      sv_setpvn(ST(0), "0", 1);
   } else {
      sv_setpvn(ST(0), "CRL: Empty File", 15);
   }
   end:
   BIO_free(in);
   if (crl) X509_CRL_free (crl);

void
hello()
   CODE:
   printf("Hello, worldd!\n");
