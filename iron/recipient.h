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

#ifndef _IRON_RECIPIENT_H
#define _IRON_RECIPIENT_H

#include "key.h"
#include "sodium.h"
#include "iron-gpg.h"
#include "iron/gpg-internal.h"

#define IRON_MAX_RECIPIENTS 11      //  Max # people with whom to share access to a file, including
                                    //  the person who generated the file.
#define IRON_MAX_LOGIN_LEN  32

/*  Public keys (signing and encryption) and associated info for the specified login.  */
typedef struct gpg_public_key {
    char       login[IRON_MAX_LOGIN_LEN + 1];
    Key        rsa_key;
    u_char     key[crypto_box_PUBLICKEYBYTES];
    u_char     fp[GPG_KEY_FP_LEN];
    u_char     signer_fp[GPG_KEY_FP_LEN];
} gpg_public_key;

extern int                      iron_get_recipients(const gpg_public_key ** recip_list);
extern const gpg_public_key   * iron_get_recipient_keys(const char * login);
extern const gpg_public_key   * iron_get_recipient_keys_by_key_id(const char * key_id);

#endif
