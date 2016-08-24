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

#ifndef _IRON_GPG_KEYFILE_H
#define _IRON_GPG_KEYFILE_H

#include "key.h"
#include "iron/recipient.h"

extern int      get_gpg_public_keys(const char * login, Key * rsa_key, u_char * rsa_fp, u_char * key,
                                    size_t * key_len, u_char * fp);

extern int      get_gpg_secret_encryption_key(const gpg_public_key * pub_keys, u_char * sec_key);

extern int      get_gpg_secret_signing_key(Key * rsa_key);

extern int	iron_index_public_keys(gpg_public_key * keys);

extern int      iron_retrieve_ssh_private_key(const char * prompt, Key ** key);

extern char *   iron_get_user_by_key_id(const char * key_id);

extern gpg_public_key * iron_get_user_keys_by_key_id(const char * key_id);

#endif
