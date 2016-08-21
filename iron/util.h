/*
 * Copyright (c) 2016 IronCore Labs <bob.wall@ironcorelabs.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _IRON_UTIL_H
#define _IRON_UTIL_H

#include "openssl/bn.h"
#include "openssl/evp.h"
#include "openssl/sha.h"

#include "key.h"
#include "sshbuf.h"


extern void     iron_hex2str(const unsigned char * hex, int hex_len, char * str);
extern int      iron_str2hex(const char * str, unsigned char * hex, int hex_len);
extern void     iron_int_to_buf(int val, unsigned char * buf);
extern int      iron_put_bignum(struct sshbuf * buf, const BIGNUM * bignum);
extern void     iron_put_num_sexpr(struct sshbuf * buf, const unsigned char * bstr, int bstr_len);
extern const char * iron_get_user_ssh_dir(const char * const login);
extern void     iron_reverse_byte_array(const unsigned char * src, unsigned char * dst, unsigned int len);
extern void     iron_reverse_byte_array_in_place(unsigned char * arr, unsigned int len);
extern void     compute_sha1_hash_sshbuf(const struct sshbuf * buf, unsigned char * hash);
extern void     compute_sha1_hash_chars(const unsigned char * bstr, int bstr_len, unsigned char * hash);
extern int      hashcrypt(SHA_CTX * sha_ctx, EVP_CIPHER_CTX * aes_ctx, const unsigned char * input, int size,
                          unsigned char * output);
extern BIGNUM * compute_rsa_signature(const unsigned char * digest, size_t digest_len, const Key * key);

#endif
