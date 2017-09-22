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


#ifndef _AESCBC_OPENSSL_H_
#define _AESCBC_OPENSSL_H_

#include <openssl/aes.h>

/**
 * @file                    aes_cbc_openssl.h
 * @author                  Katarzyna Mazur
 * @brief                   Function that performs AES-CBC encryption / decryption for testing purposes [definition]
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief                   Performs the AES-CBC encryption on the given input buffer
 * @param input             buffer to be encrypted with the AES-CBC algorithm
 * @param key               AES' encryption key
 * @param iv                initialization vector (IV) used for encryption
 * @return                  input encrypted with AES-CBC
 */
unsigned char *AESCBCEncryption(char *input, unsigned char *iv, AES_KEY key);

/**
 * @brief                   Performs the AES-CBC decryption on the given input buffer
 * @param input             buffer to be decrypted with the AES-CBC algorithm
 * @param key               AES' decryption key
 * @param iv                initialization vector (IV) used for encryption
 * @return                  input decrypted with AES-CBC
 */
unsigned char *AESCBCDecryption(char *input, unsigned char *iv, AES_KEY key);

/**
 * @brief                   Performs the AES-CBC encryption and decryption on the given input buffer
 * @param input             buffer to beencrypted and decrypted with the AES-CBC algorithm
 * @param keylength         AES' key length [bytes]
 */
void AESEncryptionDecryption(char *input, const unsigned long int keylength);

#ifdef __cplusplus
}
#endif
#endif
