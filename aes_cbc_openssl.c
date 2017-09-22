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


#include "aes_cbc_openssl.h"
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @file                    aes_cbc_openssl.c
 * @author                  Katarzyna Mazur
 * @brief                   Function that performs AES-CBC encryption / decryption for testing purposes [implementation]
 */

unsigned char *AESCBCEncryption(char *input, unsigned char *iv, AES_KEY key)
{
    unsigned int n = strlen((char *)input);
    unsigned int outputsSize = ((n + AES_BLOCK_SIZE -1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char *buff1 = (unsigned char*) malloc(sizeof(unsigned char) * (outputsSize+1));
    unsigned char *buff2 = (unsigned char*) malloc(sizeof(unsigned char) * (outputsSize+1));

    memset(buff1, 0, outputsSize+1);
    memset(buff2, 0, outputsSize+1);

    strcpy((char *)buff1, (char *)input);
    buff1[outputsSize] = buff2[outputsSize] = '\0';

    AES_cbc_encrypt(buff1, buff2, outputsSize, &key, iv, AES_ENCRYPT);

    free(buff1);
    buff1 = NULL;

    return buff2;
}

unsigned char *AESCBCDecryption(char *input, unsigned char *iv, AES_KEY key)
{
    unsigned int n = strlen((char *)input);
    unsigned char *buff1 = (unsigned char*) malloc(sizeof(unsigned char) * (n+1));
    unsigned char *buff2 = (unsigned char*) malloc(sizeof(unsigned char) * (n+1));

    memset(buff1, 0, n+1);
    memset(buff2, 0, n+1);

    strcpy((char *)buff1, (char *)input);
    buff1[n] = buff2[n] = '\0';

    AES_cbc_encrypt(buff1, buff2, n, &key, iv, AES_DECRYPT);

    free(buff1);
    buff1 = NULL;

    return buff2;
}

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

void AESEncryptionDecryption(char *input, const unsigned long int keylength)
{
    unsigned int n = strlen((char *)input), i;
    unsigned char *key = (unsigned char*) malloc(sizeof(unsigned char) * (keylength/8));
    unsigned char *encryptionIV = (unsigned char*) malloc(sizeof(unsigned char) * (AES_BLOCK_SIZE));
    unsigned char *decryptionIV = (unsigned char*) malloc(sizeof(unsigned char) * (AES_BLOCK_SIZE));
    const size_t outputsSize = ((n + AES_BLOCK_SIZE -1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char *buff1 = (unsigned char*) malloc(sizeof(unsigned char) * (outputsSize+1));
    unsigned char *buff2 = (unsigned char*) malloc(sizeof(unsigned char) * (outputsSize+1));
    unsigned char *buff3 = (unsigned char*) malloc(sizeof(unsigned char) * (outputsSize+1));
    AES_KEY encKey, decKey;

    memset(buff1, 0, outputsSize+1);
    memset(buff2, 0, outputsSize+1);
    memset(buff3, 0, outputsSize+1);

    strcpy((char *)buff1, (char *)input);
    buff1[n] = buff2[n] = buff3[n] = '\0';

    RAND_bytes(encryptionIV, AES_BLOCK_SIZE);
    memcpy(decryptionIV, encryptionIV, AES_BLOCK_SIZE);
    RAND_bytes(key, keylength/8);

    AES_set_encrypt_key(key, keylength, &encKey);
    AES_set_decrypt_key(key, keylength, &decKey);

    AES_cbc_encrypt(buff1, buff2, outputsSize, &encKey, encryptionIV, AES_ENCRYPT);
    AES_cbc_encrypt(buff2, buff3, outputsSize, &decKey, decryptionIV, AES_DECRYPT);

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
    free(key);
    key = NULL;
    free(encryptionIV);
    encryptionIV = NULL;
    free(decryptionIV);
    decryptionIV = NULL;
}
