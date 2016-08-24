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

#ifndef _IRON_GPG_INTERNAL_H
#define _IRON_GPG_INTERNAL_H

#include "includes.h"

//  These key-related constants are used in files with intertwined dependencies, so they are pulled into here
//  to untangle.
#define GPG_MAX_KEY_SIZE        512             //  # bytes a secret or public key can occupy
#define GPG_KEY_FP_LEN          20              //  Bytes in key fingerprint - same as the SHA hash length
#define GPG_KEY_ID_LEN          8               //  Bytes in key ID - the last 8 bytes of the key fingerprint
#define GPG_KEY_ID_OFFSET       (GPG_KEY_FP_LEN - GPG_KEY_ID_LEN)       //  Offset from start of fingerprint for ID

//  If you have a key fingerprint, this macro gives you a pointer to the key ID that corresponds to the FP
#define GPG_KEY_ID_FROM_FP(fp) ((fp) + GPG_KEY_ID_OFFSET)

#define IRONCORE_SUBDIR         "ironcore/"     //  subdir of ~/.ssh that holds all IronCore files


extern int          iron_initialize(void);
extern u_int32_t    iron_gpg_now();

#endif
