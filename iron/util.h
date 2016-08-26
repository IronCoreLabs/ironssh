/*
 *  Copyright (c) 2016 IronCore Labs, Inc. <bob.wall@ironcorelabs.com>
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice, this list
 *     of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice, this list
 *     of conditions and the following disclaimer in the documentation and/or other
 *     materials provided with the distribution.
 *
 *  3. Neither the name of the copyright holder nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without specific prior
 *     written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 *  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 *  THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 *  OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 *  TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _IRON_UTIL_H
#define _IRON_UTIL_H

#include "openssl/bn.h"
#include "openssl/evp.h"
#include "openssl/sha.h"

#include "key.h"
#include "sshbuf.h"


extern void     iron_hex2str(const u_char * hex, int hex_len, char * str);

extern int      iron_str2hex(const char * str, u_char * hex, int hex_len);

extern void     iron_int_to_buf(int val, u_char * buf);

extern u_int32_t iron_buf_to_int(const u_char * buf);

extern int      iron_put_bignum(struct sshbuf * buf, const BIGNUM * bignum);

extern void     iron_put_num_sexpr(struct sshbuf * buf, const u_char * bstr, int bstr_len);

extern void     iron_reverse_byte_array(const u_char * src, u_char * dst, unsigned int len);

extern void     iron_reverse_byte_array_in_place(u_char * arr, unsigned int len);

extern void     iron_compute_sha1_hash_sshbuf(const struct sshbuf * buf, u_char * hash);

extern void     iron_compute_sha1_hash_chars(const u_char * bstr, int bstr_len, u_char * hash);

extern int      iron_hashcrypt(SHA_CTX * mdc_ctx, SHA256_CTX * sig_ctx, EVP_CIPHER_CTX * aes_ctx,
                               const u_char * input, int size, u_char * output);

extern BIGNUM * iron_compute_rsa_signature(const u_char * digest, size_t digest_len, const Key * key);

#endif
