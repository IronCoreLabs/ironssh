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

extern int      extract_gpg_rsa_pubkey(const struct sshbuf * buf, Key * rsa_key);

extern int      extract_gpg_curve25519_seckey(const u_char * buf, int buf_len, const Key * ssh_key, u_char * d);

extern int      extract_gpg_ephemeral_key(const u_char * msg, const u_char ** ephem_pk);

extern int      extract_gpg_sym_key(const u_char * msg, const gpg_public_key * pub_keys, const u_char * ephemeral_pk,
                                    u_char * sym_key);

extern void     generate_gpg_curve25519_keygrip(const u_char * q, int q_len, u_char * grip);

extern void     generate_gpg_curve25519_pubkey_parms(const u_char * pub_key, int pk_len, struct sshbuf * buf);

extern struct sshbuf * generate_gpg_curve25519_seckey(const u_char * q, int q_len, const u_char * d, int d_len,
                                                      const u_char * passphrase);

extern int      generate_gpg_passphrase_from_rsa(const Key * rsa_key, char * passphrase);

extern struct sshbuf * generate_gpg_rsa_seckey(const Key * ssh_key, const u_char * passphrase);

extern int      generate_gpg_sym_key_frame(u_char * sym_key_frame);

extern int      get_gpg_curve25519_key_offset(void);

extern int      gpg_packet_is_curve25519_key(const u_char * buf, int buf_len);

#endif
