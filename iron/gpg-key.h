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

#ifndef _IRON_GPG_KEY_H
#define _IRON_GPG_KEY_H

#include "key.h"

#include "iron/gpg-packet.h"
#include "iron/recipient.h"


#define AES128_KEY_BYTES        16
#define AES256_KEY_BYTES        32
#define AES_BLOCK_SIZE          16
#define AES_WRAP_BLOCK_SIZE     8

#define S2K_SALT_BYTES          8       //  # bytes of randomly generated salt to prepend to passphrase

#define GPG_SECKEY_IV_BYTES     16      //  # bytes of randomly generated initialization vector to prepend to
                                        //  secret key parameters before encryption

#define GPG_ECC_PUBKEY_PREFIX   0x40    //  Prepended to the public key parameter q of a elliptic curve to indicate
                                        //  that it uses libgcrypt's "point compression", which is the x coordinate
                                        //  only (y is discarded). This is always the case for curve25519, so we
                                        //  always prefix q with this octet.


extern void     clamp_and_reverse_seckey(u_char * sk);

extern void     compute_gpg_key_fingerprint(const gpg_packet * pubkey_pkt, u_char * key_fp);

extern int      encrypt_gpg_key_frame(const u_char * sym_key_frame, int frame_len, const gpg_public_key * key,
                                      u_char * enc_frame, u_char * ephem_pk);

extern struct sshbuf * encrypt_gpg_sec_parms(const struct sshbuf * buf, const u_char * passphrase, u_char * salt,
                                             u_char * iv, size_t iv_len);

extern int      extract_gpg_curve25519_pubkey(const struct sshbuf * buf, u_char * key);

extern int      extract_gpg_ed25519_pubkey(const struct sshbuf * buf, u_char * key);

extern int      extract_gpg_curve25519_seckey(const u_char * buf, int buf_len, u_char * sec_key);

extern int      extract_gpg_ed25519_seckey(const u_char * buf, int buf_len, const u_char * pub_key, u_char * sec_key);

extern int      extract_gpg_ephemeral_key(const u_char * msg, const u_char ** ephem_pk);

extern int      extract_gpg_sym_key(const u_char * msg, const gpg_public_key * pub_keys, const u_char * ephemeral_pk,
                                    u_char * sym_key);

extern void     generate_gpg_ed25519_keygrip(const u_char * pub_key, u_char * grip);

extern void     generate_gpg_curve25519_keygrip(const u_char * pub_key, u_char * grip);

extern void     generate_gpg_ed25519_pubkey_parms(const u_char * pub_key, struct sshbuf * buf);

extern void     generate_gpg_curve25519_pubkey_parms(const u_char * pub_key, struct sshbuf * buf);

extern struct sshbuf * generate_gpg_curve25519_seckey(const u_char * pub_key, const u_char * sec_key,
                                                      const u_char * passphrase);

extern struct sshbuf * generate_gpg_ed25519_seckey(const u_char * pub_key, const u_char * sec_key,
                                                   const u_char * passphrase);

extern int      generate_gpg_passphrase(char * passphrase);

extern int      generate_gpg_sym_key_frame(u_char * sym_key_frame);

extern int      gpg_packet_is_ed25519_key(const u_char * buf, int buf_len);

extern int      gpg_packet_is_curve25519_key(const u_char * buf, int buf_len);

#endif
