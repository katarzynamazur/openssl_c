/****************************************************************************
**
** Copyright (c) 2014
** All rights reserved.
**
** This product includes software developed by the OpenSSL Project
** for use in the OpenSSL Toolkit (http://www.openssl.org/)
**
** You may use this file under the terms of the BSD license as follows:
**
** "Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are
** met:
**
**   * Redistributions of source code must retain the above copyright
**     notice, this list of conditions and the following disclaimer.
**   * Redistributions in binary form must reproduce the above copyright
**     notice, this list of conditions and the following disclaimer in
**     the documentation and/or other materials provided with the
**     distribution.
**
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
** "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
** LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
** A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
** OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
** DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
** THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
** OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."
**
**
****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "aes_cbc_openssl.h"

/**
 * @file                    aes_cbc_openssl_standalone.c
 * @author                  Katarzyna Mazur
 * @brief                   Standalone Openssl AES-CBC test
 */

static void hexPrint(const void* pv, size_t len)
{
    const unsigned char * p = (const unsigned char*)pv;
    if (NULL == pv)
        fprintf(stdout, "NULL");
    else
    {
        size_t i = 0;
        for (; i<len; i++)
            fprintf(stdout, "%02X ", *p++);
    }
    fprintf(stdout, "\n");
}

void testAESCBC_V1()
{
    const size_t n = 1024;
    unsigned int i;
    unsigned int keylength;
    char input[1024];
    unsigned char *key = NULL;
    unsigned char *encryptionIV = NULL;
    unsigned char *decryptionIV = NULL;
    size_t outputsSize = -1;
    unsigned char *buff1 = NULL;
    unsigned char *buff2 = NULL;
    unsigned char *buff3 = NULL;
    AES_KEY encKey, decKey;

    memset(input, '\0', 1024);

    printf("Input to be encrypted with AES in CBC mode:\n> ");
    fgets(input, n, stdin);

    i = 0;
    while(input[i] != '\0')
        i++;
    input[i-1] = '\0';

    outputsSize = ((strlen(input) + AES_BLOCK_SIZE -1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;

    printf("AES' keylength [bytes]:\n> ");
    scanf("%u", &keylength);

    if(keylength != 128 && keylength != 192 && keylength != 256)
    {
        fprintf(stdout, "\nInvalid key length!\n");
        exit(-1);
    }

    key = (unsigned char*) malloc(sizeof(unsigned char) * (keylength/8));
    RAND_bytes(key, keylength/8);

    buff1 = (unsigned char*) malloc(sizeof(unsigned char) * (outputsSize+1));
    memset(buff1, 0, outputsSize);

    strcpy((char *)buff1, (char *)input);

    encryptionIV = (unsigned char*) malloc(sizeof(unsigned char) * (AES_BLOCK_SIZE));
    decryptionIV = (unsigned char*) malloc(sizeof(unsigned char) * (AES_BLOCK_SIZE));
    RAND_bytes(encryptionIV, AES_BLOCK_SIZE);
    memcpy(decryptionIV, encryptionIV, AES_BLOCK_SIZE);

    AES_set_encrypt_key(key, keylength, &encKey);
    AES_set_decrypt_key(key, keylength, &decKey);

    buff2 = AESCBCEncryption((char *)buff1, encryptionIV, encKey);
    buff3 = AESCBCDecryption((char *)buff2, decryptionIV, decKey);

    for(i=0; i<80; i++)
        fprintf(stdout,  "-");
    fprintf(stdout,  "\n");

    fprintf(stdout, "ORIGINAL TEXT: \t\t%s\n", buff1);
    fprintf(stdout, "ENCRYPTED: \t\t");
    hexPrint(buff2, outputsSize);
    fprintf(stdout, "DECRYPTED: \t\t%s\n", buff3);

    for(i=0; i<80; i++)
        fprintf(stdout,  "-");
    fprintf(stdout,  "\n");

    free(buff1);
    buff1 = NULL;
    free(buff2);
    buff2 = NULL;
    free(buff3);
    buff3 = NULL;
    free(encryptionIV);
    encryptionIV = NULL;
    free(decryptionIV);
    decryptionIV = NULL;
    free(key);
    key = NULL;
}

void testAESCBC_V2()
{
    size_t n = 1024;
    unsigned int keylength;
    char input[1024];
    unsigned int i;

    printf("Input to be encrypted with AES in CBC mode:\n> ");
    fgets(input, n, stdin);

    i = 0;
    while(input[i] != '\0')
        i++;
    input[i-1] = '\0';

    printf("AES' keylength [bytes]:\n> ");
    scanf("%u", &keylength);

    if(keylength != 128 && keylength != 192 && keylength != 256)
    {
        fprintf(stdout, "\nInvalid key length!\n");
        exit(-1);
    }

    AESEncryptionDecryption(input, keylength);
}

int main(int argc, char **argv)
{
    testAESCBC_V1();

    return 0;
}
