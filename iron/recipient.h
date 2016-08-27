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
