#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>

// I'm not using BIO for base64 encoding/decoding.  It is difficult to use.
// Using superwills' Nibble And A Half instead 
// https://github.com/superwills/NibbleAndAHalf/blob/master/NibbleAndAHalf/base64.h
#include "ibase64.h"

// The PADDING parameter means RSA will pad your data for you
// if it is not exactly the right size
//#define PADDING RSA_PKCS1_OAEP_PADDING
#define PADDING RSA_PKCS1_PADDING
//#define PADDING RSA_NO_PADDING

RSA* loadPUBLICKeyFromString( const char* publicKeyStr )
{
  // A BIO is an I/O abstraction (Byte I/O?)
  
  // BIO_new_mem_buf: Create a read-only bio buf with data
  // in string passed. -1 means string is null terminated,
  // so BIO_new_mem_buf can find the dataLen itself.
  // Since BIO_new_mem_buf will be READ ONLY, it's fine that publicKeyStr is const.
  BIO* bio = BIO_new_mem_buf( (void*)publicKeyStr, -1 ) ; // -1: assume string is null terminated
  
  BIO_set_flags( bio, BIO_FLAGS_BASE64_NO_NL ) ; // NO NL
  
  // Load the RSA key from the BIO
  RSA* rsaPubKey = PEM_read_bio_RSA_PUBKEY( bio, NULL, NULL, NULL ) ;
  if( !rsaPubKey )
    printf( "ERROR: Could not load PUBLIC KEY!  PEM_read_bio_RSA_PUBKEY FAILED: %s\n", ERR_error_string( ERR_get_error(), NULL ) ) ;
  
  BIO_free( bio ) ;
  return rsaPubKey ;
}

RSA* loadPRIVATEKeyFromString( const char* privateKeyStr )
{
  BIO *bio = BIO_new_mem_buf( (void*)privateKeyStr, -1 );
  //BIO_set_flags( bio, BIO_FLAGS_BASE64_NO_NL ) ; // NO NL
  RSA* rsaPrivKey = PEM_read_bio_RSAPrivateKey( bio, NULL, NULL, NULL ) ;
  
  if ( !rsaPrivKey )
    printf("ERROR: Could not load PRIVATE KEY!  PEM_read_bio_RSAPrivateKey FAILED: %s\n", ERR_error_string(ERR_get_error(), NULL));
  
  BIO_free( bio ) ;
  return rsaPrivKey ;
}

unsigned char* rsaEncrypt( RSA *pubKey, const unsigned char* str, int dataSize, int *resultLen )
{
  int rsaLen = RSA_size( pubKey ) ;
  unsigned char* ed = (unsigned char*)malloc( rsaLen ) ;
  
  // RSA_public_encrypt() returns the size of the encrypted data
  // (i.e., RSA_size(rsa)). RSA_private_decrypt() 
  // returns the size of the recovered plaintext.
  *resultLen = RSA_public_encrypt( dataSize, (const unsigned char*)str, ed, pubKey, PADDING ) ; 
  if( *resultLen == -1 )
    printf("ERROR: RSA_public_encrypt: %s\n", ERR_error_string(ERR_get_error(), NULL));

  return ed ;
}

unsigned char* rsaDecrypt( RSA *privKey, const unsigned char* encryptedData, int *resultLen )
{
  int rsaLen = RSA_size( privKey ) ; // That's how many bytes the decrypted data would be
  
  unsigned char *decryptedBin = (unsigned char*)malloc( rsaLen ) ;
  *resultLen = RSA_private_decrypt( RSA_size(privKey), encryptedData, decryptedBin, privKey, PADDING ) ;
  if( *resultLen == -1 )
    printf( "ERROR: RSA_private_decrypt: %s\n", ERR_error_string(ERR_get_error(), NULL) ) ;
    
  return decryptedBin ;
}

unsigned char* makeAlphaString( int dataSize )
{
  unsigned char* s = (unsigned char*) malloc( dataSize ) ;
  
  int i;
  for( i = 0 ; i < dataSize ; i++ )
    s[i] = 65 + i ;
  s[i-1]=0;//NULL TERMINATOR ;)
  
  return s ;
}

// You may need to encrypt several blocks of binary data (each has a maximum size
// limited by pubKey).  You shoudn't try to encrypt more than
// RSA_LEN( pubKey ) bytes into some packet.
// returns base64( rsa encrypt( <<binary data>> ) )
// base64OfRsaEncrypted()
// base64StringOfRSAEncrypted
// rsaEncryptThenBase64
int rsaEncryptThenBase64( RSA *pubKey, unsigned char* binaryData, int binaryDataLen, int *outLen, unsigned char* res)
{
  int encryptedDataLen ;
  
  // RSA encryption with public key
  unsigned char* encrypted = rsaEncrypt( pubKey, binaryData, binaryDataLen, &encryptedDataLen) ;
  // To base 64
  int asciiBase64EncLen ;
  asciiBase64EncLen = base64( encrypted, encryptedDataLen, outLen, res);
  // Destroy the encrypted data (we are using the base64 version of it)
  free( encrypted ) ;
  // Return the base64 version of the encrypted data
  return asciiBase64EncLen ;
}

// rsaDecryptOfUnbase64()
// rsaDecryptBase64String()
// unbase64ThenRSADecrypt()
// rsaDecryptThisBase64()
unsigned char* rsaDecryptThisBase64( RSA *privKey, char* base64String, int *outLen, char* res)
{
  int encBinLen ;
  unsigned char* encBin = unbase64( base64String, (int)strlen( base64String ), &encBinLen) ;
  
  // rsaDecrypt assumes length of encBin based on privKey
  unsigned char *decryptedBin = rsaDecrypt( privKey, encBin, outLen ) ;
  free( encBin ) ;
  
  return decryptedBin ;
}
  


int enc(unsigned char* plaintext, int plaintext_len, unsigned char* asciiB64E)
{
  ERR_load_crypto_strings();  
  // public key
  // http://srdevspot.blogspot.ca/2011/08/openssl-error0906d064pem.html
  //1. The file must contain:
  //-----BEGIN CERTIFICATE-----
  //on a separate line (i.e. it must be terminated with a newline).
  //2. Each line of "gibberish" must be 64 characters wide.
  //3. The file must end with:
  //-----END CERTIFICATE-----
  // YOUR PUBLIC KEY MUST CONTAIN NEWLINES.  If it doesn't (ie if you generated it with
  // something like
  // ssh-keygen -t rsa -C "you@example.com"
  // ) THEN YOU MUST INSERT NEWLINES EVERY 64 CHRS (just line it up with how I have it here
  // or with how the ssh-keygen private key is formatted by default)
  const char *b64_pKey = "-----BEGIN PUBLIC KEY-----\n"
  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYEBxvQLjqdKiXHw533r2y6SPC\n"
  "DKqtYYCt2sfbXQEVDgpSU/k/BAvr/H63XfpxgaGLW2YvpNXnlfPA7HHlWibCcrpJ\n"
  "1wflLW+u7CpfiwxhsEWZnxQmoAa7H4I3HjyRaIqoZ6ADTp+KapC4Y6IoXQ3Miwgf\n"
  "eIPc8xEW9D2nhbnzfwIDAQAB\n"
  "-----END PUBLIC KEY-----\n";
  
  // private key
  const char *b64priv_key = "-----BEGIN RSA PRIVATE KEY-----\n"
"MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAJgQHG9AuOp0qJcf\n"
"DnfevbLpI8IMqq1hgK3ax9tdARUOClJT+T8EC+v8frdd+nGBoYtbZi+k1eeV88Ds\n"
"ceVaJsJyuknXB+Utb67sKl+LDGGwRZmfFCagBrsfgjcePJFoiqhnoANOn4pqkLhj\n"
"oihdDcyLCB94g9zzERb0PaeFufN/AgMBAAECgYAzqk2u8yOg7XAWoIOu8KwtbI8s\n"
"sFcRP66T42DCRJBIkhOps0RdR8exL4HyVWjxReUYTz6h83SGEenW478y+PVv164w\n"
"BuP5QBOChSuqaUI7bgR7OWpztLzEnpeIIzRroGVF2vQ51F3qb+LCVJt0KfgdBXVf\n"
"D/8e0hmL8dwGa+AHYQJBAMXymmLXHyAqfIjYvt5Dxly65whM0zlguA7dFZ/ikYYA\n"
"+/5jB6GqLnjZgQbfneGewVaxNr+QHdZrEE9IDZrkEu8CQQDEqJnuT1SijzfUY1lc\n"
"ZuAwgw+Ze+2bF3J3F3JsPNWCe58YW2f98e9za7PbewKhdkxiim6Qey5r9gJIS5U0\n"
"a+hxAkB+LIu4IQNYD3zeBbp0FqNkDEajhcTFuB7aapYUGelEj3AQ0LLWm5GPuqSB\n"
"6xvJ6tW2GrOZG5XJTOlSf80cQ/DFAkAnqR0KK6OU+S84PSULdo/mGLhvqsebjJoA\n"
"HJFt9MLWgtnuDpklZMJ205S9QcyhBXuYL/TmXIFbMoz5SYz4un5xAkAk8xGLbibj\n"
"I6Pom0dzqIPJ/8dOd0Ps0UqYBq+He+BpkKexeYagsDTovs6Cm8iRgwQ5VnEnQHMY\n"
"UTaXZS3SpTr/\n"
  "-----END RSA PRIVATE KEY-----\n";

  // String to encrypt, INCLUDING NULL TERMINATOR:
  int dataSize=37 ; // 128 for NO PADDING, __ANY SIZE UNDER 128 B__ for RSA_PKCS1_PADDING
  unsigned char *str = makeAlphaString( dataSize ) ;

  // LOAD PUBLIC KEY
  RSA *pubKey = loadPUBLICKeyFromString( b64_pKey ) ;

  int asciiB64ELen;
  asciiB64ELen = rsaEncryptThenBase64( pubKey, plaintext, plaintext_len, &asciiB64ELen, asciiB64E) ;
  RSA_free( pubKey ) ; // free the public key when you are done all your encryption
  
  return asciiB64ELen;
}