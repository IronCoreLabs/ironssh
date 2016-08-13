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

#ifndef _IRON_GPG_H
#define _IRON_GPG_H

#include "sodium.h"
#include "sshbuf.h"


#define COMMENT_MAX				128		//  Max # bytes in the comment on a public SSH key

#define GPG_MAX_KEY_SIZE		512		//  # bytes a secret or public key can occupy
#define AES128_KEY_BYTES		16
#define AES256_KEY_BYTES		32
#define GPG_KEY_FP_LEN			20		//  Bytes in key fingerprint - same as the SHA hash length
#define GPG_KEY_ID_LEN			8		//  Bytes in key ID - the last 8 bytes of the key fingerprint
#define GPG_KEY_ID_OFFSET		(GPG_KEY_FP_LEN - GPG_KEY_ID_LEN)	//  Offset from start of fingerprint for ID


extern int	check_iron_keys(const char * const login);
extern int	write_gpg_encrypted_file(const char * fname, int write_tmpfile, char * enc_fname);
extern int	write_gpg_decrypted_file(const char * login, const char * fname, char * dec_fname);

extern void reset_recipients();
extern int  add_recipient(const char * login);
extern int  remove_recipient(const char * login);

#endif  /* _IRON_GPG_H */
