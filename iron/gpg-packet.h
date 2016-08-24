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

#ifndef _IRON_GPG_PACKET_H
#define _IRON_GPG_PACKET_H

#include <stdio.h>

#include "openssl/evp.h"
#include "openssl/sha.h"

#include "iron/gpg-internal.h"
#include "iron/recipient.h"


/*  Tags used to indicate the types of GPG packets.  */
typedef enum gpg_tag {
    GPG_TAG_DO_NOT_USE          = 0,
    GPG_TAG_PKESK               = 1,    //  Public-key encrypted session key
    GPG_TAG_SIGNATURE           = 2,
    GPG_TAG_SKESK               = 3,    //  Symmetric-key encrypted session key
    GPG_TAG_ONE_PASS_SIGNATURE  = 4,
    GPG_TAG_SECRET_KEY          = 5,
    GPG_TAG_PUBLIC_KEY          = 6,
    GPG_TAG_SECRET_SUBKEY       = 7,
    GPG_TAG_COMPRESSED_DATA     = 8,
    GPG_TAG_SYM_ENCRYPTED_DATA  = 9,
    GPG_TAG_MARKER              = 10,
    GPG_TAG_LITERAL_DATA        = 11,
    GPG_TAG_TRUST               = 12,
    GPG_TAG_USERID              = 13,
    GPG_TAG_PUBLIC_SUBKEY       = 14,
    GPG_TAG_USER_ATTRIBUTE      = 17,
    GPG_TAG_SEIP_DATA           = 18,   //  Symmetrically encrypted and integrity protected data
    GPG_TAG_MOD_DETECT_CODE     = 19,
    GPG_TAG_RESERVED1           = 60,   //  Reserved for private/experimental use
    GPG_TAG_RESERVED2           = 61,
    GPG_TAG_RESERVED3           = 62,
    GPG_TAG_RESERVED4           = 63
} gpg_tag;

/*  Public key encryption algorithm identifiers. The _E suffix indicates encryption-only, _S indicates signing-only,
 *  and _ES can be used for either.
 */
typedef enum gpg_pk_algo {
    GPG_PKALGO_RSA_ES           = 1,
    GPG_PKALGO_RSA_E            = 2,
    GPG_PKALGO_RSA_S            = 3,
    GPG_PKALGO_ELGAMAL_E        = 16,
    GPG_PKALGO_DSA              = 17,
    GPG_PKALGO_ECDH             = 18,
    GPG_PKALGO_ECDSA            = 19,
    GPG_PKALGO_RESERVED20       = 20,   //  Was ELGAMAL_ES
    GPG_PKALGO_DH               = 21,   //  X9.42
    GPG_PKALGO_EDDSA            = 22,   //  EdDSA (Ed25519 support)
    GPG_PKALGO_RESERVED100      = 100,  //  Private/experimental algorithms
    GPG_PKALGO_RESERVED101      = 101,
    GPG_PKALGO_RESERVED102      = 102,
    GPG_PKALGO_RESERVED103      = 103,
    GPG_PKALGO_RESERVED104      = 104,
    GPG_PKALGO_RESERVED105      = 105,
    GPG_PKALGO_RESERVED106      = 106,
    GPG_PKALGO_RESERVED107      = 107,
    GPG_PKALGO_RESERVED108      = 108,
    GPG_PKALGO_RESERVED109      = 109,
    GPG_PKALGO_RESERVED110      = 110
} gpg_pk_algo;

/*  Symmetric key encryption algorithm identifiers.  */
typedef enum gpg_sk_algo {
    GPG_SKALGO_PLAINTEXT        = 0,
    GPG_SKALGO_IDEA             = 1,
    GPG_SKALGO_TRIPLEDES        = 2,
    GPG_SKALGO_CAST5            = 3,    //  128-bit key
    GPG_SKALGO_BLOWFISH         = 4,    //  128-bit key, 16 rounds
    GPG_SKALGO_RESERVED5        = 5,
    GPG_SKALGO_RESERVED6        = 6,
    GPG_SKALGO_AES128           = 7,
    GPG_SKALGO_AES192           = 8,
    GPG_SKALGO_AES256           = 9,
    GPG_SKALGO_TWOFISH256       = 10,
    GPG_SKALGO_CAMELLIA128      = 11,
    GPG_SKALGO_CAMELLIA192      = 12,
    GPG_SKALGO_CAMELLIA256      = 13,
    GPG_SKALGO_RESERVED100      = 100,  //  Private/experimental algorithms
    GPG_SKALGO_RESERVED101      = 101,
    GPG_SKALGO_RESERVED102      = 102,
    GPG_SKALGO_RESERVED103      = 103,
    GPG_SKALGO_RESERVED104      = 104,
    GPG_SKALGO_RESERVED105      = 105,
    GPG_SKALGO_RESERVED106      = 106,
    GPG_SKALGO_RESERVED107      = 107,
    GPG_SKALGO_RESERVED108      = 108,
    GPG_SKALGO_RESERVED109      = 109,
    GPG_SKALGO_RESERVED110      = 110
} gpg_sk_algo;

/*  Compress algorithm identifiers.  */
typedef enum gpg_compression_algo {
    GPG_COMPALGO_UNCOMP         = 0,
    GPG_COMPALGO_ZIP            = 1,
    GPG_COMPALGO_ZLIB           = 2,
    GPG_COMPALGO_BZIP           = 3,
    GPG_COMPALGO_RESERVED100    = 100,  //  Private/experimental algorithms
    GPG_COMPALGO_RESERVED101    = 101,
    GPG_COMPALGO_RESERVED102    = 102,
    GPG_COMPALGO_RESERVED103    = 103,
    GPG_COMPALGO_RESERVED104    = 104,
    GPG_COMPALGO_RESERVED105    = 105,
    GPG_COMPALGO_RESERVED106    = 106,
    GPG_COMPALGO_RESERVED107    = 107,
    GPG_COMPALGO_RESERVED108    = 108,
    GPG_COMPALGO_RESERVED109    = 109,
    GPG_COMPALGO_RESERVED110    = 110
} gpg_compression_algo;

/*  Hash algorithm identifiers.  */
typedef enum gpg_hash_algo {
    GPG_HASHALGO_MD5            = 1,
    GPG_HASHALGO_SHA1           = 2,
    GPG_HASHALGO_RIPE_MD160     = 3,
    GPG_HASHALGO_SHA256         = 8,
    GPG_HASHALGO_SHA384         = 9,
    GPG_HASHALGO_SHA512         = 10,
    GPG_HASHALGO_SHA224         = 11,
    GPG_HASHALGO_RESERVED100    = 100,  //  Private/experimental algorithms
    GPG_HASHALGO_RESERVED101    = 101,
    GPG_HASHALGO_RESERVED102    = 102,
    GPG_HASHALGO_RESERVED103    = 103,
    GPG_HASHALGO_RESERVED104    = 104,
    GPG_HASHALGO_RESERVED105    = 105,
    GPG_HASHALGO_RESERVED106    = 106,
    GPG_HASHALGO_RESERVED107    = 107,
    GPG_HASHALGO_RESERVED108    = 108,
    GPG_HASHALGO_RESERVED109    = 109,
    GPG_HASHALGO_RESERVED110    = 110
} gpg_hash_algo;


/*  Types of signature packets  */
typedef enum gpg_signature_class {
    GPG_SIGCLASS_BINARY_DOC     = 0,
    GPG_SIGCLASS_TEXT_DOC       = 1,
    GPG_SIGCLASS_STANDALONE     = 2,
    GPG_SIGCLASS_GENERIC_CERT   = 16,
    GPG_SIGCLASS_PERSONA_CERT   = 17,
    GPG_SIGCLASS_CASUAL_CERT    = 18,
    GPG_SIGCLASS_POSITIVE_CERT  = 19,
    GPG_SIGCLASS_SUBKEY_BIND    = 24,
    GPG_SIGCLASS_PRIM_KEY_BIND  = 25,
    GPG_SIGCLASS_KEY            = 31,
    GPG_SIGCLASS_KEY_REVOKE     = 32,
    GPG_SIGCLASS_SUBKEY_REVOKE  = 40,
    GPG_SIGCLASS_CERT_REVOKE    = 48,
    GPG_SIGCLASS_TIMESTAMP      = 64
} gpg_signature_class;

/*  Type specifiers for subpackets in a Public Key or Secret Key packet  */
typedef enum gpg_signature_subpket_type {
    GPG_SIG_SUBPKT_SIGNATURE_CREATION_TIME  = 2,        // time_t
    GPG_SIG_SUBPKT_SIGNATURE_LIFETIME       = 3,        // 4 octets - # seconds after creation
    GPG_SIG_SUBPKT_EXPORTABLE               = 4,        // boolean
    GPG_SIG_SUBPKT_TRUST                    = 5,        // 1 octet level, 1 octet amount
    GPG_SIG_SUBPKT_REGEX                    = 6,        // null-terminated string
    GPG_SIG_SUBPKT_REVOCABLE                = 7,        // boolean
    GPG_SIG_SUBPKT_KEY_LIFETIME             = 9,        // 4 octets - # seconds after creation
    GPG_SIG_SUBPKT_PREF_SYM_ALGO            = 11,       // list of one octet algo IDs
    GPG_SIG_SUBPKT_REVOCATION_KEY           = 12,       // 1 octet class, 1 octet PK algo, 20 octet fingerprint
    GPG_SIG_SUBPKT_ISSUER                   = 16,       // 8 octet key ID
    GPG_SIG_SUBPKT_NOTATION_DATA            = 20,       // 4 octet flags, 2 octet name len, 2 octet val len,
                                                        //   name data, val data
    GPG_SIG_SUBPKT_PREF_HASH_ALGO           = 21,       // list of one octet algo IDs
    GPG_SIG_SUBPKT_PREF_COMPRESS_ALGO       = 22,       // list of one octet algo IDs
    GPG_SIG_SUBPKT_KEY_SERVER_PREFS         = 23,       // n octets of flags
    GPG_SIG_SUBPKT_PREF_KEY_SERVER          = 24,       // URI of key server
    GPG_SIG_SUBPKT_PRIMARY_USER_ID          = 25,       // boolean
    GPG_SIG_SUBPKT_POLICY_URI               = 26,       // URI
    GPG_SIG_SUBPKT_KEY_FLAGS                = 27,       // n octets
    GPG_SIG_SUBPKT_SIGNER_USER_ID           = 28,       //
    GPG_SIG_SUBPKT_REVOCATION_REASON        = 29,       //
    GPG_SIG_SUBPKT_FEATURES                 = 30,       // n octets of flags
    GPG_SIG_SUBPKT_SIGNATURE_TARGET         = 31,       //
    GPG_SIG_SUBPKT_EMBEDDED_SIGNATURE       = 32,       //
    GPG_SIG_SUBPKT_EXP_100                  = 100,      // Experimental / private codes
    GPG_SIG_SUBPKT_EXP_101                  = 101,
    GPG_SIG_SUBPKT_EXP_102                  = 102,
    GPG_SIG_SUBPKT_EXP_103                  = 103,
    GPG_SIG_SUBPKT_EXP_104                  = 104,
    GPG_SIG_SUBPKT_EXP_105                  = 105,
    GPG_SIG_SUBPKT_EXP_106                  = 106,
    GPG_SIG_SUBPKT_EXP_107                  = 107,
    GPG_SIG_SUBPKT_EXP_108                  = 108,
    GPG_SIG_SUBPKT_EXP_109                  = 109,
    GPG_SIG_SUBPKT_EXP_110                  = 110
} gpg_signature_subpket_type;


#define GPG_KEY_VERSION         4       //  Current version for public key and public subkey packets
#define GPG_SIG_VERSION         4       //  Current version for signature packets
#define GPG_PKESK_VERSION       3       //  Current version for public key encrypted session key packets
#define GPG_OPS_VERSION         3       //  Current version for one pass signature packets
#define GPG_SEIPD_VERSION       1       //  Current version for symmetrically encrypted integrity protected data pkts

#define GPG_MDC_PKT_LEN         22      //  Two byte tag + len, 20 byte SHA1 hash


/*  Wrapper for a complete GPG packet - body is just stored in an sshbuf.  */
typedef struct gpg_packet {
    gpg_tag         tag;
    ssize_t         len;
    struct sshbuf * data;
} gpg_packet;


extern int      extract_gpg_tag_and_size(const u_char * buf, gpg_tag * tag, ssize_t * size);

extern int      extract_gpg_one_pass_signature_packet(const u_char * buf, int buf_len, u_char * key_id);

extern int      finalize_gpg_data_signature_packet(SHA256_CTX * sig_ctx, Key * rsa_key, gpg_packet * sig_pkt);

extern void     generate_gpg_curve25519_subkey_packet(const u_char * pub_key, size_t pk_len, gpg_packet * pkt);

extern void     generate_gpg_data_signature_packet(const Key * rsa_key, const u_char * key_id, gpg_packet * sig_pkt);

extern int      generate_gpg_literal_data_packet(const char * fname, size_t file_len, time_t mod_time,
                                 u_char * data_pkt_hdr);

extern void     generate_gpg_one_pass_signature_packet(const u_char * key_id, gpg_packet * ops_pkt);

extern void     generate_gpg_pk_uid_signature_packet(const gpg_packet * pubkey_pkt, const gpg_packet * uid_pkt,
                                                     const Key * key, int sig_class, const u_char * key_id,
                                                     gpg_packet * pkt);

extern int      generate_gpg_pkesk_packet(const gpg_public_key * key, u_char * sym_key_frame, int frame_len,
                                          gpg_packet * pkt);

extern void     generate_gpg_public_key_packet(const Key * ssh_key, gpg_packet * pkt);

extern void     generate_gpg_seipd_packet_hdr(int data_len, gpg_packet * pkt);

extern int      generate_gpg_tag_and_size(gpg_tag tag, ssize_t size, u_char * buf);

extern void     generate_gpg_trust_packet(gpg_packet * pkt);

extern void     generate_gpg_user_id_packet(const char * user_id, gpg_packet * pkt);

extern gpg_packet * get_gpg_curve25519_key_packet(FILE * infile);

extern int      get_gpg_pkesk_packet(FILE * infile, const char * key_id, u_char * msg, gpg_tag * next_tag,
                                     int * next_len);

extern gpg_packet * get_gpg_pub_key_packet(FILE * infile);

extern int      process_data_signature_packet(const u_char * dec_buf, int buf_len, SHA256_CTX * sig_ctx,
                                              const u_char * rsa_key_id);

extern int      put_gpg_packet(FILE * outfile, const gpg_packet * msg);

extern int      write_gpg_mdc_packet(FILE * outfile, SHA_CTX * sha_ctx, EVP_CIPHER_CTX * aes_ctx);

#endif
