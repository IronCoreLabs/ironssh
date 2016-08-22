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

#include "includes.h"

#include <string.h>
#include <sys/types.h>
#include <errno.h>

#include "openssl/bn.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "openssl/sha.h"

#include "authfd.h"
#include "authfile.h"
#include "cipher.h"
#include "digest.h"
#include "digest.h"
#include "log.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "uuencode.h"

#include "sodium.h"

#include "iron-gpg.h"
#include "iron/gpg-internal.h"
#include "iron/gpg-key.h"
#include "iron/gpg-keyfile.h"
#include "iron/gpg-packet.h"
#include "iron/util.h"


//  Parameters and related constants for the String-to-Key (S2K) algorithm used by GPG.
#define S2K_USAGE               254         //  Other options are 0 or 255, but we'll always use 254
#define S2K_SPEC                3           //  Iterated + salted S2K. There are Other options, but we'll always use 3
#define S2K_ITER_BYTE_COUNT     20971520    //  # of bytes to produce by iterating S2K hash
#define S2K_ITER_ENCODED        228         //  Encoding of byte count in RVC 2440 / 4880 format

#define PRE_ENC_PPHRASE_BYTES   33      //  Number of bytes of RSA signature to use as passphrase (pre-base64 encoding)
#define PPHRASE_LEN             4 * ((PRE_ENC_PPHRASE_BYTES + 2) / 3) + 1       //  +1 for null terminator

#define GPG_PUB_PARM_PREFIX     "(5:curve10:Curve25519)(5:flags9:djb-tweak)(1:q"
#define GPG_SEC_PARM_PREFIX     "(9:protected25:openpgp-s2k3-sha1-aes-cbc((4:sha18:"

#define PROTECTED_AT_LEN        36      //  # chars in (12:protected-at15:<date>) string (w/ null terminator)

/*  Curve 25519 parameters P, A, B, N, G_X, G_Y, H)
    P   = "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED",     prime
    A   = "0x01DB41",                                                               A coefficient of curve
    B   = "0x01",                                                                   B coefficient of curve
    N   = "0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED",     order of base point
    G_X = "0x0000000000000000000000000000000000000000000000000000000000000009",     base point X
    G_Y = "0x20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9",     base point Y
    H   = "0x08"                                                                    cofactor
*/

static u_char curve25519_p[] = {
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed
};
static u_char curve25519_a[] = {
    0x01, 0xdb, 0x41
};
static u_char curve25519_b[] = {
    0x01
};
static u_char curve25519_g[] = {
    0x04,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
    0x20, 0xae, 0x19, 0xa1, 0xb8, 0xa0, 0x86, 0xb4, 0xe0, 0x1e, 0xdd, 0x2c, 0x77, 0x48, 0xd1, 0x4c,
    0x92, 0x3d, 0x4d, 0x7e, 0x6d, 0x7c, 0x61, 0xb2, 0x29, 0xe9, 0xc5, 0xa2, 0x7e, 0xce, 0xd3, 0xd9
};
static u_char curve25519_n[] = {
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed
};

/*  The OID for Curve25519 in OpenPGP format. This represents the text OID 1.3.6.1.4.1.3029.1.5.1  */
static const char curve25519_oid[] = {
    0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01
};

/*  The third public key parameter that goes with the OID and the actual public key value - the first two
 *  bytes are fixed, and the last two bytes specify the hash algorithm (08 == SHA256) and symmetric key
 *  algorithm (07 == AES128) that are used to generate a key encryption key (KEK) to encrypt data once
 *  Curve25519 is used to compute a shared secret.
 */
static const char curve25519_kek_parm[] = {
    0x03, 0x01, 0x08, 0x07
};

struct curve25519_param_entry {
    char param_name;
    u_char * value;
    int len;
};

struct curve25519_param_entry curve25519_param[] = {
    { 'p', curve25519_p, sizeof(curve25519_p) },
    { 'a', curve25519_a, sizeof(curve25519_a) },
    { 'b', curve25519_b, sizeof(curve25519_b) },
    { 'g', curve25519_g, sizeof(curve25519_g) },
    { 'n', curve25519_n, sizeof(curve25519_n) }
};


/**
 *  Check whether the body of a packet is a curve25519 key
 *
 *  Look at the start of the packet body (a public or secret key or subkey) and verify that it is a
 *  curve25519 key packet.
 *
 *  @param buf byte array holding packet body
 *  @param buf_len num bytes in buf
 *  return int 1 if cv25519 key, 0 otherwise
 */
int
gpg_packet_is_curve25519_key(const u_char * buf, int buf_len)
{
#define GPG_SUBKEY_PKALGO_OFFSET    5       //  # bytes at start of packet body before the algorithm type

    if (buf_len < (int) (GPG_SUBKEY_PKALGO_OFFSET + 1 + sizeof(curve25519_oid)) ||
        buf[GPG_SUBKEY_PKALGO_OFFSET] != GPG_PKALGO_ECDH ||
        memcmp(buf + GPG_SUBKEY_PKALGO_OFFSET + 1, curve25519_oid, sizeof(curve25519_oid)) != 0) {
        return 0;
    } else {
        return 1;
    }
}

/**
 *  Return the offset from start of packet to find cv25519 public key value
 *
 *  This is the number of bytes from the start of a public or secret key or subkey packet to skip to find
 *  the start of a curve25519 public key value (as an MPI, with two byte bit length prefix).
 */
int
get_gpg_curve25519_key_offset(void)
{
    return GPG_SUBKEY_PKALGO_OFFSET + 1 + sizeof(curve25519_oid);
}

/**
 *  Do cv25519 "clamp" operation then reverse key byte array.
 *
 *  Deep in the bowels of the key generation, the secret key was "clamped" before generating the public
 *  key, but it didn't actually change the bits in the secret key it returned. We'll go ahead and do that,
 *  to avoid confusion.
 *
 *  Also, libsodium's secret key has the low-order byte first, but libgcrypt/gpg has the high-order byte
 *  first. So just run through and reverse the secret key.
 *  For some inexplicable reason, the public key doesn't need to be reversed. I so wish I understood why.
 *
 *  @param sk Byte array containing secret key (should be crypto_box_SECRETKEYBYTES bytes)
 */
void
clamp_and_reverse_seckey(u_char * sk)
{
    //  "Clamping" - Zero lowest three bits and highest bit of secret key, set next-to-highest bit. But
    //  libsodium/nacl represents the components little-endian (least signficant byte first).
    sk[crypto_box_SECRETKEYBYTES - 1] &= 0x7f;
    sk[crypto_box_SECRETKEYBYTES - 1] |= 0x40;
    sk[0] &= 0xf8;
    iron_reverse_byte_array_in_place(sk, crypto_box_SECRETKEYBYTES);
}

/**
 *  Generate GPG keygrip for RSA key.
 *
 *  The GPG keygrip is a shortened representation (i.e. hash) of the parameters of the public key. The hash
 *  is just SHA1. The RSA keygrip is so much simpler than the curve25519 one - an RSA keygrip is just a SHA1
 *  hash of the public key parameter n.
 *
 *  @param key RSA key (only needs public params populated)
 *  @param grip Place to write keygrip. At least SHA_DIGEST_LENGTH bytes.
 */
void
generate_gpg_rsa_keygrip(const Key * rsa_key, u_char * grip)
{
	u_char   tmp_n[2 * GPG_MAX_KEY_SIZE + 1];
	u_char * tmp_ptr;

	//  Extract the public key parameter n from the bignum, prepend a zero if necessary to make
	//  sure the high bit isn't set, then hash.
	tmp_n[0] = 0x00;
	int n_len = BN_bn2bin(rsa_key->rsa->n, tmp_n + 1);
	if (tmp_n[1] > 0x7f) {
		n_len++;
		tmp_ptr = tmp_n;
	} else {
		tmp_ptr = tmp_n + 1;
	}

	iron_compute_sha1_hash_chars(tmp_ptr, n_len, grip);
}

/**
 *  Generate GPG keygrip for curve25519 key.
 *
 *  The GPG keygrip is a shortened representation (i.e. hash) of the parameters of the public key. The hash
 *  is just SHA1.
 *
 *  @param q Curve25519 public key
 *  @param q_len Num bytes in q
 *  @param grip Place to write keygrip. At least SHA_DIGEST_LENGTH bytes.
 */
void
generate_gpg_curve25519_keygrip(const u_char * q, int q_len, u_char * grip)
{
    struct sshbuf * b = sshbuf_new();
    char buf[32];
    struct curve25519_param_entry * ptr = curve25519_param;
    int len;

    for (size_t ct = 0; ct < sizeof(curve25519_param) / sizeof(struct curve25519_param_entry); ct++) {
        len = snprintf(buf, sizeof(buf), "(1:%c%u:", ptr->param_name, ptr->len);
        sshbuf_put(b, buf, len);
        sshbuf_put(b, ptr->value, ptr->len);
        sshbuf_put_u8(b, ')');
        ptr++;
    }

    //  Can't use iron_put_num_sexpr here, because in this context, GPG doesn't add the preceding 00 octet if the
    //  high bit of the first octet is set. Thanks for the consistency, GPG.
    //iron_put_num_sexpr(b, q, q_len);
    sshbuf_putf(b, "(1:q%d:", q_len);
    sshbuf_put(b, q, q_len);
    sshbuf_put_u8(b, ')');
    iron_compute_sha1_hash_sshbuf(b, grip);
}

/**
 *  Compute String-to-Key (s2k) key from passphrase.
 *
 *  Uses the GPG algorithm to convert a passphrase into a key that can be used for symmetric key encryption.
 *  Why use a standard PBKDF?
 *
 *  If we are going to encrypt with AES256, we need 32 bytes of key. To generate, we concatenate the 8 bytes
 *  of random salt and the passphrase. This string will be hashed repeatedly to generate the key.
 *  We are using SHA1 for the hash, which outputs 20 bytes, and we are generating an AES128 key, which is 16
 *  bytes, so we only need one hashes. If a key of more than 20 bytes is needed, we need to set up multiple hash
 *  contexts, so that the output of each of them concatenated together generates the requested number of bytes.
 *  So, for example, if a 21 to 40 byte key is needed, we would create two hash contexts. If a 41 to 60 byte key
 *  is needed, we would create three hash contexts, etc.
 *
 *  To generate different data from each hash, each successive hash is initialized with one more byte of zeroes.
 *  The first hash has no initializer, the second has one byte of zeros, the third has two bytes, etc.
 *
 *  The caller should provide eight bytes of random salt to use that as a prefix for the passphrase. This new
 *  string is hashed repeatedly by each hash, until we have hashed exactly S2K_ITER_BYTE_COUNT bytes. The key
 *  is formed by concatenating the output of the hashes, discarding the rightmost bytes of the last hash when
 *  we have enough bytes for the key.
 *
 *  Yes, GPG is so special that regardless of what you specify for a hash algorithm, it's going to use SHA1.
 *  Thanks, GPG.
 *
 *  @param passphrase ASCII string to transform into key
 *  @param key_len Num bytes to generate
 *  @param salt Byte array of random salt to prefix
 *  @param bytes_to_hash Count of bytes to run through hash function (large number to make key harder to crack)
 *  @param key Place to write generated key (should be key_len bytes)
 */
static void
compute_gpg_s2k_key(const char * passphrase, int key_len, const u_char * salt, int bytes_to_hash,
                    u_char * key)
{
    int len = strlen(passphrase) + S2K_SALT_BYTES;
    u_char * salted_passphrase = malloc(len);

    memcpy(salted_passphrase, salt, S2K_SALT_BYTES);
    memcpy(salted_passphrase + S2K_SALT_BYTES, passphrase, len - S2K_SALT_BYTES);

    static u_char zero_buf[1] = {'\0'};

    int num_hashes = (key_len + SHA_DIGEST_LENGTH - 1) / SHA_DIGEST_LENGTH;
    SHA_CTX * hash = calloc(num_hashes, sizeof(SHA_CTX));

    int ct;
    for (ct = 0; ct < num_hashes; ct++) {
        SHA1_Init(&(hash[ct]));
        for (int ct2 = 0; ct2 < ct; ct2++) {
            SHA1_Update(&(hash[ct]), zero_buf, 1);
        }
    }

    /* Always hash at least one full string of salt + passphrase. */
    if (bytes_to_hash < len) {
        bytes_to_hash = len;
    }

    while (bytes_to_hash > len) {
        for (ct = 0; ct < num_hashes; ct++) {
            SHA1_Update(&(hash[ct]), salted_passphrase, len);
        }
        bytes_to_hash -= len;
    }
    /* Handle the last (potentially) partial block. We need to stop at exactly the specified number of bytes. */
    for (ct = 0; ct < num_hashes; ct++) {
        SHA1_Update(&(hash[ct]), salted_passphrase, bytes_to_hash);
    }

    free(salted_passphrase);
    int num_bytes_left;
    u_char * key_ptr = key;
    for (ct = 0, num_bytes_left = key_len; num_bytes_left > 0; num_bytes_left -= SHA_DIGEST_LENGTH, ct++) {
        u_char digest[SHA_DIGEST_LENGTH];
        int bytes_to_copy = (num_bytes_left < SHA_DIGEST_LENGTH) ? num_bytes_left : SHA_DIGEST_LENGTH;
        SHA1_Final(digest, &(hash[ct]));
        memcpy(key_ptr, digest, bytes_to_copy);
        key_ptr += bytes_to_copy;
    }

    free(hash);
}

/**
 *  Create a passphrase from an SSH RSA key
 *
 *  Generate a text passphrase to secure the GPG secret keys created from an SSH RSA key. This is a
 *  somewhat tricky proposition - we want to have the ability to generate this passphrase tied to the
 *  ability to access the SSH key, and we want to take advantage of the ssh-agent's caching of private
 *  key info. So we are going to hash the RSA public key, then attempt to sign it. This should send a
 *  request to the ssh-agent, and if the agent isn't available or doesn't have the RSA key cached, should
 *  prompt the user for the passphrase. The signature is as long as the RSA key, which is a lot. We take
 *  the first 32 bytes of the passphrase and base64 encode them to form the passphrase.
 *
 *  @param rsa_key Byte array containing the public RSA key
 *  @param passphrase Place to put generated passphrase (at least PPHRASE_LEN bytes)
 *  @returns int 0 if successful, negative number if error
 */
int
generate_gpg_passphrase_from_rsa(const Key * rsa_key, char * passphrase)
{
    static int    cached_len = -1;
    static u_char cached_params[GPG_MAX_KEY_SIZE * 2];
    static char    cached_passphrase[PPHRASE_LEN];

    u_char params[GPG_MAX_KEY_SIZE * 2];
    int params_len = BN_bn2bin(rsa_key->rsa->n, params);
    params_len += BN_bn2bin(rsa_key->rsa->e, params + params_len);

    if (params_len == cached_len && memcmp(cached_params, params, params_len) == 0) {
        strcpy(passphrase, cached_passphrase);
        return 0;
    }

    int retval = -1;

    //  Ask the agent to sign the params. (It will actually compute a hash from the data and sign that.)
    //  If the agent isn't running, retrieve the private key and sign the params in process (will prompt
    //  for passphrase for secret RSA key).
    u_char * signature = NULL;
    size_t   sig_len;
    int      agent_fd;

    if (ssh_get_authentication_socket(&agent_fd) == 0) {
        //  Using this busted old SHA1 hash because even fairly recent versions of ssh-agent seem to
        //  ignore "rsa-sha2-256" and just pick "ssh-rsa" anyway.
        if (ssh_agent_sign(agent_fd, (Key *) rsa_key, &signature, &sig_len, params, params_len,
                           "ssh-rsa", 0) != 0) {
            signature = NULL;
        }
    }

    if (signature == NULL) {
        //  No authentication agent, or the authentication agent didn't have the secret key, means we
        //  need user's private key to sign the hash. If the private params are set in the provided sshkey,
        //  just use them. Otherwise, need to fetch them from the user's private key file.
        Key * key = NULL;
        if (rsa_key->rsa->d == NULL) {
            //  Private key not populated - fetch from file
            const char * ssh_dir = iron_get_user_ssh_dir(iron_user_login());
            if (ssh_dir != NULL) {
                int rv = iron_retrieve_ssh_private_key(ssh_dir, "To decrypt file, enter passphrase for SSH key: ",
                                                       &key);
                if (rv != 0) {
                    error("Unable to retrieve SSH key: %s", ssh_err(rv));
                    retval = -2;
                    key = NULL;
                }
            } else {
                error("Unable to retrieve SSH key - no .ssh dir for login %s", iron_user_login());
                retval = -3;
            }
        } else {
            key = (Key *) rsa_key;
        }

        if (key != NULL) {
            int rv = sshkey_sign(key, &signature, &sig_len, params, params_len, "ssh-rsa", 0);
            if (rv != 0) {
                error("Error generating signature for passphrase - %s.", ssh_err(rv));
                retval = -4;
            }
        }
        if (key != rsa_key) {
            sshkey_free(key);
        }
    }

    if (signature != NULL) {
        u_char * sptr = signature;
		u_int32_t len = iron_buf_to_int(sptr);
		sptr += 4 + len;
		len = iron_buf_to_int(sptr);
		sptr += 4;
        if ((sig_len - len) != (size_t) (sptr - signature)) {
            error("Unrecognized format for RSA signature. Unable to generate passphrase.");
            retval = -5;
        } else {
            uuencode(sptr, PRE_ENC_PPHRASE_BYTES, passphrase, PPHRASE_LEN);

            cached_len = params_len;
            memcpy(cached_params, params, params_len);
            strcpy(cached_passphrase, passphrase);

            retval = 0;
        }
        free(signature);
    }

    return retval;
}

/**
 *  Compute the fingerprint for a public key
 *
 *  Compute a key fingerprint, which is a hash of the public key parameters. Of course, this can't
 *  be as simple as just hashing the public key / subkey packet. Thanks GPG. Even if it is a subkey
 *  (which is a new format packet), GPG hashes 0x99 and a two-byte length as the start of the packet.
 *  Luckily, with RSA and ECDH key packets at least, that is the only tweak necessary to generate a
 *  fingerprint for a key or subkey that matches GPG.
 *
 *  @param pubkey_pkt The serialized public key packet containing the key parameters
 *  @param key_fp Pointer to place to store computed fingerprint. Should be at least SHA_DIGEST_LENGTH bytes
 */
void
compute_gpg_key_fingerprint(const gpg_packet * pubkey_pkt, u_char * key_fp)
{
    SHA_CTX  ctx;
    u_char   hdr[3];

    SHA1_Init(&ctx);
    //  Generate a packet header that is always a public key packet with two byte length.
    hdr[0] = 0x99;
    hdr[1] = pubkey_pkt->len >> 8;
    hdr[2] = pubkey_pkt->len;
    SHA1_Update(&ctx, hdr, 3);
    SHA1_Update(&ctx, sshbuf_ptr(pubkey_pkt->data), sshbuf_len(pubkey_pkt->data));
    SHA1_Final(key_fp, &ctx);
}

/**
 *  Generate a Key Encryption Key.
 *
 *  When a symmetric key is used for a PGP message, it needs to be encrypted to a specific user. This requires
 *  the generation of a Key Encryption Key (KEK). This requires the fingerprint of the recipient's key and a
 *  shared point computed using Elliptic Curve Diffie Hellman (ECDH). The KEK is a SHA256 hash of these parameters
 *  plus some related info. We are using AES128 for the key encryption, so we just use use the first bytes of
 *  the hash as the KEK.
 *
 *  @param fp Fingerprint of recipient's main (signing) key
 *  @param shared_point Output of ECDH algorithm given ephemeral secret key and recipient's public key
 *  @param kek Place to put generated kek. Should point to at least AES128_KEY_BYTES bytes
 */
static void
generate_gpg_kek(const u_char * fp, const u_char * shared_point, u_char * kek)
{
#define SENDER_STRING "Anonymous Sender    "

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    u_char buf[] = { 0x00, 0x00, 0x00, 0x01  };

    SHA256_Update(&ctx, buf, sizeof(buf));

    SHA256_Update(&ctx, shared_point, crypto_box_BEFORENMBYTES);
    SHA256_Update(&ctx, curve25519_oid, sizeof(curve25519_oid));
    buf[0] = GPG_PKALGO_ECDH;
    SHA256_Update(&ctx, buf, 1);
    SHA256_Update(&ctx, curve25519_kek_parm, sizeof(curve25519_kek_parm));
    SHA256_Update(&ctx, SENDER_STRING, strlen(SENDER_STRING));
    SHA256_Update(&ctx, fp, GPG_KEY_FP_LEN);

    u_char digest[SHA256_DIGEST_LENGTH];
    SHA256_Final(digest, &ctx);
    memcpy(kek, digest, AES128_KEY_BYTES);
}

/**
 *  Generate the public parameters for a CV25519 key
 *
 *  Format the public parms into an sshbuf that can be written to a public key file.
 *
 *  @param pub_key key value to write
 *  @param pk_len num bytes in pub_key
 *  @param buf place to write the generated params
 */
void
generate_gpg_curve25519_pubkey_parms(const u_char * pub_key, int pk_len, struct sshbuf * buf)
{
    sshbuf_put(buf, curve25519_oid, sizeof(curve25519_oid));

    /* A bit more GPG/libgcrypt fun - the public key parameter q needs to be prefixed by an octet that indicates
     * that it is only the x coordinate. However, we need the unprefixed key for other uses, so we need to remember
     * to add the prefix only in the necessary spots. Bad GPG! Anyway, create a separate copy of the parameter that
     * includes the prefix to put into the public subkey packet.
     */
    u_char * prefixed_pk = malloc(pk_len + 1);
    *prefixed_pk = GPG_ECC_PUBKEY_PREFIX;
    memcpy(prefixed_pk + 1, pub_key, pk_len);
    BIGNUM * pk = BN_new();
    BN_bin2bn(prefixed_pk, pk_len + 1, pk);
    iron_put_bignum(buf, pk);
    BN_clear_free(pk);
    free(prefixed_pk);

    //  The last parameter specifies the hash algorithm and the encryption algorithm used to derive the key
    //  encryption key (KEK).
    sshbuf_put(buf, curve25519_kek_parm, sizeof(curve25519_kek_parm));
}

/**
 *  Recover the RSA public key from pubkey packet body.
 *
 *  Will fill in the n and e parameters in the rsa_key.
 *
 *  @param buf Pubkey packet body
 *  @param rsa_key Place to write recovered RSA public key. Caller needs to RSA_free rsa_key->rsa
 *  @return int 0 if successful, negative number if error
 */
#define MIN_PUBKEY_PKT_LEN 14       //  version, 4-byte timestamp, algo, 2 2-byte MPI lengths, 2 2-byte MPIs

int
extract_gpg_rsa_pubkey(const struct sshbuf * buf, Key * rsa_key)
{
    int retval = -1;
    const u_char * ptr = sshbuf_ptr(buf);
    int len = sshbuf_len(buf);
    if (len >= MIN_PUBKEY_PKT_LEN) {
        ptr += 5;                   //  Skip version, 4-byte timestamp
        if (*ptr == GPG_PKALGO_RSA_ES) {    //  Make sure the algorithm is what we expect
            ptr++;
            int key_len = (*ptr << 8) + *(ptr + 1);
            ptr += 2;
            key_len = (key_len + 7) / 8;    //  Convert from bites to bytes
            if (key_len <= GPG_MAX_KEY_SIZE) {
                RSA_free(rsa_key->rsa);
                rsa_key->rsa = RSA_new();
                rsa_key->rsa->n = BN_new();
                BN_bin2bn(ptr, key_len, rsa_key->rsa->n);
                ptr += key_len;
                //  Now grab the e value (another MPI)
                key_len = (*ptr << 8) + *(ptr + 1);
                ptr += 2;
                key_len = (key_len + 7) / 8;    //  Convert from bites to bytes
                rsa_key->rsa->e = BN_new();
                BN_bin2bn(ptr, key_len, rsa_key->rsa->e);
                retval = 0;
            }
        }
    }

    return retval;
}

/**
 *  Find ephemeral public key in input buffer.
 *
 *  Locate the ephemeral public key that was used to generate the shared secret. It is an MPI (with
 *  preceding length in bits, and the 0x40 prefix indicating it is just the X coordinate of the point)
 *  right after the algorithm specifier.
 *
 *  @param msg pointer to buffer of remaining data from the PKESK packet
 *  @param ephem_pk output pointer to the start of the ephemeral public key in that buffer
 *  @return number of bytes consumed from msg
 */
int
extract_gpg_ephemeral_key(const u_char * msg, const u_char ** ephem_pk)
{
    int retval = -1;
    const u_char * msg_ptr = msg;
    int epk_len = (*msg_ptr << 8) + *(msg_ptr + 1);
    epk_len = (epk_len + 7) / 8;        //  Convert from bits to bytes
    msg_ptr += 2;
    if (*msg_ptr == GPG_ECC_PUBKEY_PREFIX) {
        msg_ptr++;
        epk_len--;
        if (epk_len == crypto_box_PUBLICKEYBYTES) {
            *ephem_pk = msg_ptr;
            msg_ptr += epk_len;
            retval = msg_ptr - msg;
        } else {
            error("Length of recovered ephemeral key incorrect - cannot recover data.");
        }
    } else {
        error("Ephemeral key format incorrect - cannot recover data.");
    }

    return retval;
}

/**
 *  Encrypt secret parameters.
 *
 *  Encrypt the S-expression containing secret key parameters using AES128 in CBC mode.
 *  The AES key is generated using 8 bytes of random salt and a passphrase, using the PGP S2K algorithm.
 *  and AES is initialized with a randomly generated IV (initialization vector).
 *
 *  A pseudo-nonce is achieved by adding 8 bytes of random data after the S-expression before encrypting.
 *
 *  @param buf S-expression to encrypt
 *  @param passphrase ASCII string used to generate AES key
 *  @param salt Place to write 8 bytes of salt that are generated
 *  @param iv Place to write initialization vector. At least GPG_SECKEY_IV_BYTES
 *  @param iv_len Num bytes to write into IV
 *  @return sshbuf * Buffer containing encrypted S-expression, or NULL if error. Caller should sshbuf_free
 */
struct sshbuf *
encrypt_gpg_sec_parms(const struct sshbuf * buf, const u_char * passphrase, u_char * salt,
                      u_char * iv, size_t iv_len)
{
    struct sshbuf * obuf = NULL;

    u_char key[AES128_KEY_BYTES];

    randombytes_buf(salt, S2K_SALT_BYTES);
    compute_gpg_s2k_key(passphrase, sizeof(key), salt, S2K_ITER_BYTE_COUNT, key);
    randombytes_buf(iv, iv_len);

    struct sshcipher_ctx ciphercontext;
    const struct sshcipher * cipher = cipher_by_name("aes128-cbc");

    memset(&ciphercontext, 0, sizeof(ciphercontext));
    int retval = cipher_init(&ciphercontext, cipher, key, sizeof(key), iv, iv_len, CIPHER_ENCRYPT);

    if (retval == 0) {
        u_char * input = malloc(sshbuf_len(buf) + AES128_KEY_BYTES);
        memcpy(input, sshbuf_ptr(buf), sshbuf_len(buf));
        randombytes_buf(input + sshbuf_len(buf), AES128_KEY_BYTES);
        int enc_len = AES128_KEY_BYTES * ((sshbuf_len(buf) + AES128_KEY_BYTES) / AES128_KEY_BYTES);
        u_char * output;
        obuf = sshbuf_new();
        sshbuf_reserve(obuf, enc_len, &output);
        retval = cipher_crypt(&ciphercontext, 0, output, input, enc_len, 0, 0);
        free(input);
        if (retval != 0) {
            sshbuf_free(obuf);
            obuf = NULL;
        }
    }

    return obuf;
}

/**
 *  Decrypt symmetric key frame.
 *
 *  Decrypt a frame encrypted by encrypt_gpg_key_frame - the reciever needs to derive the same key then
 *  call this routine, which uses aes128-wrap to decrypt the block. The result should end up 8 bytes shorter
 *  than the encrypted frame.
 *
 *  @param enc_frame Encrypted frame to decrypt
 *  @param frame_len Num bytes in enc_frame
 *  @param key Generated Key Encryption Key
 *  @param frame Place to write decrypted frame. Should point to at least AES256_KEY_BYTES + AES_WRAP_BLOCK_SIZE bytes
 *  @return int Num bytes in frame, or negative number if error
 */
static int
decrypt_gpg_key_frame(const u_char * enc_frame, int frame_len, const u_char * key,
                      u_char * frame)
{
    EVP_CIPHER_CTX ciphctx;
    const EVP_CIPHER * cipher = EVP_aes_128_wrap();

    int written = -1;

    EVP_CIPHER_CTX_init(&ciphctx);
    EVP_CIPHER_CTX_set_flags(&ciphctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if (EVP_DecryptInit_ex(&ciphctx, cipher, NULL /* dflt engine */, key, NULL /* dflt iv */)) {
        int z = EVP_DecryptUpdate(&ciphctx, frame, &written, enc_frame, frame_len);
        if (z) {
            int tmp_written;
            if (EVP_DecryptFinal_ex(&ciphctx, frame + written, &tmp_written)) {
                written += tmp_written;
            }
        }
        else ERR_print_errors_fp(stdout);
    }
    EVP_CIPHER_CTX_cleanup(&ciphctx);
    return written;
}

/**
 *  Create ephemeral (random) key pair and compute shared secret for recipient.
 *
 *  Choose an ephemeral Curve25519 key pair (random value for secret and the corresponding public point),
 *  then multiply the secret value by the recipient's public key. This is standard ECDH.
 *
 *  @param recip_pk Public Curve25519 key of recipient
 *  @param ephem_pk Place to write ephemeral public key. Should point to crypto_box_PUBLICKEYBYTES bytes
 *  @param secret Place to write shared secret. Should point to crypto_box_BEFORENMBYTES bytes
 */
static void
generate_curve25519_ephem_shared_secret(const u_char * recip_pk, u_char * ephem_pk,
                                        u_char *secret)
{
    u_char ephem_sk[crypto_box_SECRETKEYBYTES];

    crypto_box_keypair(ephem_pk, ephem_sk);
    crypto_scalarmult_curve25519(secret, ephem_sk, recip_pk);
    sodium_memzero(ephem_sk, sizeof(ephem_sk));
}

/**
 *  Create shared secret given recipient's secret key and sender's public key.
 *
 *  Compute the Curve25519 shared secret, given recipient's secret key and sender's public key.
 *  Multiply our secret key by the sender's public key (in this case, the ephemeral key that was included
 *  in the message), and this will match the secret the sender computed by multiplying their secret key by
 *  our public key.
 *
 *  Need to reverse the secret key we read from the file before we can multiply it by the point to account
 *  for endianness differences between libsodium and libgcrypt.
 *
 *  @param sec_key Recipient's secret key. Should be crypto_box_SECRETKEYBYTES bytes
 *  @param pub_key Sender's public key. Should be crypto_box_PUBLICKEYBYTES bytes
 *  @param secret Place to write shared secret. Should be crypto_box_BEFORENMBYTES bytes
 */
static void
generate_curve25519_shared_secret(const u_char * sec_key, const u_char * pub_key, u_char * secret)
{
    u_char tseckey[crypto_box_SECRETKEYBYTES];
    iron_reverse_byte_array(sec_key, tseckey, crypto_box_SECRETKEYBYTES);
    crypto_scalarmult_curve25519(secret, tseckey, pub_key);
}

/**
 *  Recover the symmetric key from the input PKESK packet.
 *
 *  Given the body of a PKESK (Public Key Encrypted Symmetric Key) packet, find the start of the encrypted
 *  symmetric key frame, generate the KEK (Key Encryption Key), decrypt the frame, and copy the symmetric
 *  key out of it.
 *
 *  @param msg Pointer to the remainder of the PKESK body
 *  @param secret Pointer to the shared secret derived by Curve25519. Should be crypto_box_BEFORENMBYTES long
 *  @param fp Pointer to the computed fingerprint for the key. Should be GPG_KEY_FP_LEN bytes long
 *  @param sym_key Pointer to the buffer into which to copy the retrieved key. Should be AES256_KEY_BYTES long
 *  @return Number of bytes processed from msg, negative number if error
 */
int
extract_gpg_sym_key(const u_char * msg, const gpg_public_key * pub_keys, const u_char * ephem_pk,
                    u_char * sym_key)
{
    int retval = -1;

    u_char sec_key[crypto_box_SECRETKEYBYTES];
    if (get_gpg_secret_encryption_key(pub_keys, sec_key) < 0) return -3;

    u_char secret[crypto_box_BEFORENMBYTES];
    generate_curve25519_shared_secret(sec_key, ephem_pk, secret);

    u_char kek[AES256_KEY_BYTES];
    u_char frame[AES256_KEY_BYTES + AES_WRAP_BLOCK_SIZE];

    generate_gpg_kek(pub_keys->fp, secret, kek);
    int enc_frame_len = *(msg++);
    int frame_len = decrypt_gpg_key_frame(msg, enc_frame_len, kek, frame);
    if (frame_len == sizeof(frame) && *frame == GPG_SKALGO_AES256) {
        //  The first byte of the frame is the encryption algorithm - skip.
        memcpy(sym_key, frame + 1, AES256_KEY_BYTES);
        //  Add one to the encrypted frame length to account for the byte before the frame that contained the length
        retval = enc_frame_len + 1;
    } else {
        error("Unable to recover symmetric key - cannot recover data.");
    }

    return retval;
}

/**
 *  Generate the "protected-at" string for GPG packet.
 *
 *  Format the current time in ISO format (YYYYmmddTHHMMSS) and write into an S-expression for
 *  "protected-at".
 *
 *  @param str Place to write S-expression. At least PROTECTED_AT_LEN chars
 */
static void
generate_gpg_protected_at(char * str)
{
#define ISO_DT_LEN 16

    char now_iso[ISO_DT_LEN];
    time_t gpg_now = iron_gpg_now();
    strftime(now_iso, sizeof(now_iso), "%Y%m%dT%H%M%S", gmtime(&gpg_now));
    sprintf(str, "(12:protected-at15:%s)", now_iso);
}

/**
 *  Write RSA public parameter S-expression to sshbuf.
 *
 *  Generate an S-expression containing the RSA public parameters (n and e) and write the string
 *  to an sshbuf.
 *
 *  @param ssh_key RSA key
 *  @return sshbuf * Pointer to sshbuf containing S-expression. Caller should ssh_free.
 */
static struct sshbuf *
generate_gpg_rsa_pub_parms(const Key * ssh_key)
{
    struct sshbuf * pub_parms = sshbuf_new();
    u_char tmp[512];
    int len = BN_bn2bin(ssh_key->rsa->n, tmp);
    sshbuf_put(pub_parms, "(1:n", 4);
    iron_put_num_sexpr(pub_parms, tmp, len);
    len = BN_bn2bin(ssh_key->rsa->e, tmp);
    sshbuf_put(pub_parms, ")(1:e", 5);
    iron_put_num_sexpr(pub_parms, tmp, len);
    sshbuf_put_u8(pub_parms, ')');

    return pub_parms;
}

/**
 *  Write a parenthesized S-expression into buffer.
 *
 *  Given one of the parameters for a public or secret key (all of which have one-character names, like 'p' or 'n'),
 *  generate a string like "(1:q5:@1234)".
 *
 *  @param buf Place to write S-expression
 *  @param parm_name One-character name for parameter
 *  @param bn Value to write for parameter
 */
static void
put_parm_in_sexpr(struct sshbuf * buf, char parm_name, BIGNUM * bn)
{
	u_char tmp[2 * GPG_MAX_KEY_SIZE];
    int len = BN_bn2bin(bn, tmp);
    sshbuf_put(buf, "(1:", 3);
    sshbuf_put_u8(buf, parm_name);
    iron_put_num_sexpr(buf, tmp, len);
    sshbuf_put_u8(buf, ')');
}

/**
 *  Retrieve an RSA parameter value from an S-expr
 *
 *  Read the param value from byte array containing an S_Expression of the form "(1:<paramName><len>:<param>)"
 *  and stick that param value into a bignum.
 *
 *  @param buf Byte array to read
 *  @param parm_name Something like 'd', 'p', 'q', etc.
 *  @param bn Pointer to place to create and populate BIGNUM to hold param value
 *  @return int Num bytes consumed from buf if successful, negative number if error
 */
static int
get_parm_from_sexpr(const u_char * buf, char parm_name, BIGNUM ** bn)
{
	int retval = -1;
	u_char tmp[8];
	const u_char * ptr = buf;

	sprintf(tmp, "(1:%c", parm_name);
	if (strncmp(ptr, tmp, 4) == 0) {
		ptr += 4;
		errno = 0;
		int bn_len = strtol(ptr, (char **) &ptr, 10);
		ptr++;  // Skip ':'
		if (errno != EINVAL && errno != ERANGE && bn_len > 0) {
			*bn = BN_new();
			if (*bn != NULL) {
				BN_bin2bn(ptr, bn_len, *bn);
				ptr += bn_len;
				if (*(ptr++) == ')') {
					retval = ptr - buf;
				}
			}
		}
	}

	return retval;
}

/**
 *  Write RSA secret parameter S-expression to sshbuf.
 *
 *  Generate an S-expression containing the RSA secret parameters (d, p, q, u) and write the string
 *  to an sshbuf.
 *
 *  A little bit of fun - OpenSSL stores the p and q parameter such that p > q, while GPG/libgcrypt expect p < q.
 *  Also, OpenGPG expects parameter u = p^(-1) mod q, while OpenSSL has iqmp = q^(-1) mod p. Luckily, when we swap
 *  p and q, that automagically changes iqmp to u, without any recomputation.
 *
 *  @param ssh_key RSA key
 *  @return sshbuf * Pointer to sshbuf containing S-expression, or NULL if error. Caller should ssh_free.
 */
static struct sshbuf *
generate_gpg_rsa_sec_parms(const Key * ssh_key)
{
    struct sshbuf * sec_parms = sshbuf_new();
    if (sec_parms != NULL) {
        put_parm_in_sexpr(sec_parms, 'd', ssh_key->rsa->d);
        put_parm_in_sexpr(sec_parms, 'p', ssh_key->rsa->q); // The p-q swapperoo
        put_parm_in_sexpr(sec_parms, 'q', ssh_key->rsa->p); // The p-q swapperoo, part 2
        put_parm_in_sexpr(sec_parms, 'u', ssh_key->rsa->iqmp);
    }

    return sec_parms;
}

/**
 *  Decrypt secret key data
 *
 *  Unencrypt the block containing the secret key parameters, given the SSH RSA key (to generate the
 *  passphrase), the salt, and the IV. Then extract the secret key params from the S-expression.
 *
 *  @param enc_data Byte array containing encrypted key
 *  @param len Num bytes in enc_data
 *  @param rsa_pubkey RSA public key (used to generate passphrase that protects the GPG key)
 *  @param salt Byte array of random salt (should be GPG_S2K_SALT_BYTES long)
 *  @param hash_bytes Num bytes to run through S2K hash to generate key
 *  @param iv Byte array containing initialization vector (should be GPG_SECKEY_IV_LEN bytes)
 *  @return u_char * Decrypted parameter expression, or NULL if error. Caller should free
 */
static u_char *
decrypt_gpg_sec_parms(const u_char * enc_data, int len, const Key * rsa_pubkey, const u_char * salt, 
					  int hash_bytes, const u_char * iv)
{
	char * output = NULL;

	//  First, generate the passphrase from the RSA key and generate the symmetric key from that.
	u_char sym_key[AES128_KEY_BYTES];
	char   passphrase[PPHRASE_LEN];

	if (generate_gpg_passphrase_from_rsa(rsa_pubkey, passphrase) == 0) {
		compute_gpg_s2k_key(passphrase, sizeof(sym_key), salt, hash_bytes, sym_key);

		struct sshcipher_ctx ciphercontext;
		const struct sshcipher * cipher = cipher_by_name("aes128-cbc");
		if (cipher_init(&ciphercontext, cipher, sym_key, sizeof(sym_key), iv, GPG_SECKEY_IV_BYTES,
				   		CIPHER_DECRYPT) == 0) {
			output = malloc(len);
			if (output != NULL) {
				if (cipher_crypt(&ciphercontext, 0, output, enc_data, len, 0, 0) != 0) {
					free(output);
					output = NULL;
				}
			}
		}
	}

	return output;
}

/**
 *  Recover secret key parameters from S-expression
 *
 *  Finds the part of the S-expression containing the secret key parameters, decrypts it, and returns the
 *  nested S-expression containing the secret key parameters.
 *
 *  @param pub_parm_name Name of the preceding public parameter in S-Expr ('n' for RSA, 'q' for cv25519)
 *  @param key_name Name of the algorithm corresponding to the key (for error msgs)
 *  @param buf Byte array containing S-expression
 *  @param buf_len Num bytes in buf
 *  @param ssh_key RSA key used to protect GPG key
 *  @return u_char * S-expression containing parms, or NULL if error. Caller should free
 */
static u_char *
extract_gpg_sec_parms(char pub_parm_name, const char * key_name, const u_char * buf, int buf_len,
					  const Key * rsa_pubkey)
{
	u_char * sec_parms = NULL;

	//  Need to find the start of the secret key params in the S-expression. Complicated by the fact
	//  that the public key might contain binary data, so we need to skip over it to find the secret
	//  key. We do rely on the fact that the first pub_parm_name character in the string should be the
	//  start of the public key, and everything before that is ASCII. (Works for both n, for RSA keys,
	//  and q, for cv25519 keys.)
	u_char * ptr = memchr(buf, pub_parm_name, buf_len);
	if (ptr != NULL) {
		ptr++;
		errno = 0;
		int len = strtol(ptr, (char **) &ptr, 10);
		ptr++;  // Skip ':'
		if (errno == EINVAL || errno == ERANGE || len <= 0 || len > GPG_MAX_KEY_SIZE) goto out;
		ptr += len;

		//  If it's a GPG key, there is a second public parameter, e, to skip
		if (pub_parm_name == 'n') {
			if (strncmp(ptr, ")(1:e", 5) != 0) goto out;
			ptr += 5;
			errno = 0;
			int len = strtol(ptr, (char **) &ptr, 10);
			ptr++;  // Skip ':'
			if (errno == EINVAL || errno == ERANGE || len <= 0 || len > GPG_MAX_KEY_SIZE) goto out;
			ptr += len;
		}

		if (*(ptr++) != ')' || (strncmp(ptr, GPG_SEC_PARM_PREFIX, strlen(GPG_SEC_PARM_PREFIX)) != 0)) goto out;
		ptr += strlen(GPG_SEC_PARM_PREFIX);

		//  Next grab the 8 byte salt for the SHA1 hash
		u_char salt[S2K_SALT_BYTES];
		memcpy(salt, ptr, sizeof(salt));
		ptr += sizeof(salt);

		//  Get the hash byte count - skip the "8:" preceding
		ptr += 2;
		errno = 0;
		int hash_bytes = strtol(ptr, (char **) &ptr, 10);
		if (errno == EINVAL || errno == ERANGE || strncmp(ptr, ")16:", 4) != 0) goto out;
		ptr += 4;

		//  Grab the 16-byte IV for the encrypted key
		u_char iv[GPG_SECKEY_IV_BYTES];
		memcpy(iv, ptr, sizeof(iv));
		ptr += sizeof(iv);

		if (*(ptr++) != ')') goto out;
		errno = 0;
		len = strtol(ptr, (char **) &ptr, 10);
		ptr++;  // Skip ':'
		if (errno == EINVAL || errno == ERANGE || ((ptr - buf) + len) >= buf_len - 1) goto out;

		//  ptr now points to the encrypted security parameters. Take that data, along with the necessary info
		//  to decrypt, and get the secret parameters decrypted. The decrypted byte array should be as long as
		//  the encrypted one.
		sec_parms = decrypt_gpg_sec_parms(ptr, len, rsa_pubkey, salt, hash_bytes, iv);

		ptr += len;
		if (*ptr != ')') {
			free(sec_parms);
			sec_parms = NULL;
		}
	}

out:
	if (sec_parms == NULL) {
		error("Invalid format - unable to retrieve %s secret key.", key_name);
	}
	return sec_parms;
}

/**
 *  Recover RSA secret key from S-expression
 *
 *  Finds the part of the S-expression containing the secret key, decrypts it, and recovers the key.
 *
 *  @param buf Byte array containing S-expression
 *  @param rsa_key RSA key used to protect GPG key - will be populated with secret parms
 *  @return int 0 if successful, negative number if error
 */
int
extract_gpg_rsa_seckey(const u_char * buf, int buf_len, Key * rsa_key)
{
	int retval = -1;

	//  Need to find the start of the secret key params in the S-expression. Complicated by the fact
	//  that the public key might contain binary data, so we need to skip over it to find the secret
	//  key. We do rely on the fact that the first 'q' in the string should be the start of the public
	//  key, and everything before that is ASCII.
	u_char * sec_parms = extract_gpg_sec_parms('n', "RSA", buf, buf_len, rsa_key);
	if (sec_parms != NULL) {
		if (strncmp(sec_parms, "(((1:d", 6) == 0) {
			u_char * ptr = sec_parms + 2;	//  Skip opening parens

			int len = get_parm_from_sexpr(ptr, 'd', &(rsa_key->rsa->d));
			if (len > 0) {
				ptr += len;

				len = get_parm_from_sexpr(ptr, 'p', &(rsa_key->rsa->q));		//  p-q swap
				if (len > 0) {
					ptr += len;
					len = get_parm_from_sexpr(ptr, 'q', &(rsa_key->rsa->p));	//  Swap, part 2
					if (len > 0) {
						ptr += len;
						len = get_parm_from_sexpr(ptr, 'u', &(rsa_key->rsa->iqmp));
						if (len > 0) {
							retval = 0;
						}
					}
				}
			}
		}
		free(sec_parms);
	}

	if (retval != 0) {
		error("Improperly formatted data in decrypted RSA secret key - unable to process.");
	}
	return retval;
}

/**
 *  Recover cv25519 secret key from S-expression
 *
 *  Finds the part of the S-expression containing the secret key, decrypts it, and recovers the key.
 *
 *  @param buf Byte array containing S-expression
 *  @param ssh_key RSA key used to protect GPG key
 *  @param d Place to write secret key (should be crypto_box_SECRETKEYBYTES bytes)
 *  @return int Num bytes written to d, negative number if error
 */
int
extract_gpg_curve25519_seckey(const u_char * buf, int buf_len, const Key * ssh_key, u_char * d)
{
    int retval = -1;

    //  Need to find the start of the secret key params in the S-expression. Complicated by the fact
    //  that the public key might contain binary data, so we need to skip over it to find the secret
    //  key. We do rely on the fact that the first 'q' in the string should be the start of the public
    //  key, and everything before that is ASCII.
	u_char * sec_parms = extract_gpg_sec_parms('q', "Curve25519", buf, buf_len, ssh_key);
	if (sec_parms != NULL) {
		if (strncmp(sec_parms, "(((1:d", 6) == 0) {
			u_char * ptr = sec_parms + 6;
			errno = 0;
			unsigned long len = strtoul(ptr, (char **) &ptr, 10);
			if (errno != EINVAL && errno != ERANGE && len <= (crypto_box_SECRETKEYBYTES + 2) &&
					*(ptr++) == ':') {
				int pad_len = crypto_box_SECRETKEYBYTES - len;
				if (pad_len > 0) {
					memset(d, 0, pad_len);
				}

				memcpy(d + pad_len, ptr, len);
				retval = len;
			} else {
				error("Improperly formatted data in decrypted secret key - unable to process.");
			}
		} else {
			error("Improperly formatted data in decrypted secret key - unable to process.");
		}
		free(sec_parms);
	}

    return retval;
}

/**
 *  Generate S-expression containing RSA parameters.
 *
 *  Creates the S-expression that contains each of the parameters of the RSA key - first the public key
 *  (n and e), then a nested S-expression containing the secret key (d, p, q, u). The latter is encrypted
 *  before writing into the final S-expression.
 *
 *  NOTE: The passphrase is ASCII instead of UTF-8 or some other more inclusive format because it is not
 *  entered by the user, it is a base64-encoded hash of the RSA secret key plus salt.
 *
 *  @param ssh_key RSA key
 *  @param passphrase ASCII string used to protect encrypted portion
 *  @return sshbuf * Buffer containing S-expression. Caller should sshbuf_free
 */
struct sshbuf *
generate_gpg_rsa_seckey(const Key * ssh_key, const u_char * passphrase)
{
	/* First, we need to compute the hash of the key data. The string to be hashed is unfortunately not quite
	 * exactly the same format as the subsequent string to write to the key, so for now we won't worry about
	 * reusing pieces and parts.
	 */
	struct sshbuf * seckey = NULL;
	char protected_at[PROTECTED_AT_LEN];

	generate_gpg_protected_at(protected_at);

	struct sshbuf * pub_parms = generate_gpg_rsa_pub_parms(ssh_key);
	struct sshbuf * sec_parms = generate_gpg_rsa_sec_parms(ssh_key);
	struct sshbuf * hash_str = sshbuf_new();
	struct sshbuf * sec_str = sshbuf_new();

	if (pub_parms != NULL && sec_parms != NULL && hash_str != NULL && sec_str != NULL) {
		sshbuf_put(hash_str, "(3:rsa", 6);
		sshbuf_putb(hash_str, pub_parms);
		sshbuf_putb(hash_str, sec_parms);
		sshbuf_put(hash_str, protected_at, strlen(protected_at));
		sshbuf_put_u8(hash_str, ')');

		u_char hash[SHA_DIGEST_LENGTH];
		iron_compute_sha1_hash_sshbuf(hash_str, hash);

		sshbuf_put(sec_str, "((", 2);
		sshbuf_putb(sec_str, sec_parms);
		sshbuf_put_u8(sec_str, ')');
		sshbuf_putf(sec_str, "(4:hash4:sha1%lu:", sizeof(hash));
		sshbuf_put(sec_str, hash, sizeof(hash));
		sshbuf_put(sec_str, "))", 2);

		u_char salt[S2K_SALT_BYTES];
		u_char iv[GPG_SECKEY_IV_BYTES];
		struct sshbuf * enc_sec_parms = encrypt_gpg_sec_parms(sec_str, passphrase, salt, iv, sizeof(iv));
		if (enc_sec_parms != NULL) {
			seckey = sshbuf_new();
			if (seckey != NULL) {
				sshbuf_putf(seckey, "(21:protected-private-key(3:rsa");
				sshbuf_putb(seckey, pub_parms);
				sshbuf_put(seckey, GPG_SEC_PARM_PREFIX, strlen(GPG_SEC_PARM_PREFIX));
				sshbuf_put(seckey, salt, sizeof(salt));
				sshbuf_putf(seckey, "8:%08d)%d:", S2K_ITER_BYTE_COUNT, (int) sizeof(iv));
				sshbuf_put(seckey, iv, sizeof(iv));
				sshbuf_putf(seckey, ")%lu:", sshbuf_len(enc_sec_parms));
				sshbuf_put(seckey, sshbuf_ptr(enc_sec_parms), sshbuf_len(enc_sec_parms));
				sshbuf_put_u8(seckey, ')');
				sshbuf_put(seckey, protected_at, strlen(protected_at));
				sshbuf_put(seckey, "))", 2);
			}
			sshbuf_free(enc_sec_parms);
		}
	}
	sshbuf_free(pub_parms);
	sshbuf_free(sec_parms);
	sshbuf_free(hash_str);
	sshbuf_free(sec_str);

	return seckey;
}

/**
 *  Generate S-expression for Cv25519 public key parameter.
 *
 *  @param q Curve25519 public key
 *  @param q_len Num bytes in q
 *  @return sshbuf * S-expression. Caller should sshbuf_free
 */
static struct sshbuf *
generate_gpg_curve25519_pub_parms(const u_char * q, int q_len)
{
    struct sshbuf * pub_parms = sshbuf_new();
    sshbuf_put(pub_parms, GPG_PUB_PARM_PREFIX, strlen(GPG_PUB_PARM_PREFIX));
    iron_put_num_sexpr(pub_parms, q, q_len);
    sshbuf_put_u8(pub_parms, ')');

    return pub_parms;
}

/**
 *  Generate S-expression for Cv25519 secret key parameter.
 *
 *  @param d Curve25519 secret key
 *  @param d_len Num bytes in d
 *  @return sshbuf * S-expression. Caller should sshbuf_free
 */
static struct sshbuf *
generate_gpg_curve25519_sec_parms(const u_char * d, int d_len)
{
    struct sshbuf * sec_parms = sshbuf_new();
    sshbuf_put(sec_parms, "(1:d", 4);
    iron_put_num_sexpr(sec_parms, d, d_len);
    sshbuf_put_u8(sec_parms, ')');

    return sec_parms;
}

/**
 *  Generate S-expression containing cv25519 key (public and secret parts)
 *
 *  Formats the GPG S-expression that holds an entire cv25519 key pair. The secret key is encrypted.
 *
 *  @param q Byte array containing public key
 *  @param q_len Num bytes in q
 *  @param d Byte array containing secret key
 *  @param d_len Num bytes in d
 *  @param passphrase ASCII string used to generate key to encrypt secret key
 *  @return sshbuf * Buffer containing S-expression. Caller should sshbuf_free
 */
struct sshbuf *
generate_gpg_curve25519_seckey(const u_char * q, int q_len, const u_char * d, int d_len, const u_char * passphrase)
{
    /* First, we need to compute the hash of the key data. The string to be hashed is unfortunately not quite
     * exactly the same format as the subsequent string to write to the key, so for now we won't worry about
     * reusing pieces and parts.
     */
    char protected_at[PROTECTED_AT_LEN];

    generate_gpg_protected_at(protected_at);

    /* A bit more GPG/libgcrypt fun - the public key parameter q needs to be prefixed by an octet that indicates
     * that it is only the x coordinate. However, we don't do this when generating the keygrip for the key. Bad
     * GPG! Anyway, create a separate copy of the parameter that includes the prefix and use that in the appropriate
     * places.
     */
    u_char * prefixed_q = malloc(q_len + 1);
    *prefixed_q = GPG_ECC_PUBKEY_PREFIX;
    memcpy(prefixed_q + 1, q, q_len);

    struct sshbuf * pub_parms = generate_gpg_curve25519_pub_parms(prefixed_q, q_len + 1);
    struct sshbuf * sec_parms = generate_gpg_curve25519_sec_parms(d, d_len);

    struct sshbuf * hash_str = sshbuf_new();

    sshbuf_putf(hash_str, "(3:ecc");
    sshbuf_putb(hash_str, pub_parms);
    sshbuf_putb(hash_str, sec_parms);
    sshbuf_put(hash_str, protected_at, strlen(protected_at));
    sshbuf_put_u8(hash_str, ')');

    u_char hash[SHA_DIGEST_LENGTH];
    iron_compute_sha1_hash_sshbuf(hash_str, hash);

    struct sshbuf * sec_str = sshbuf_new();
    sshbuf_put_u8(sec_str, '(');
    sshbuf_put_u8(sec_str, '(');
    sshbuf_putb(sec_str, sec_parms);
    sshbuf_put_u8(sec_str, ')');
    sshbuf_putf(sec_str, "(4:hash4:sha1%lu:", sizeof(hash));
    sshbuf_put(sec_str, hash, sizeof(hash));
    sshbuf_put_u8(sec_str, ')');
    sshbuf_put_u8(sec_str, ')');

    u_char salt[S2K_SALT_BYTES];
    u_char iv[GPG_SECKEY_IV_BYTES];
    struct sshbuf * enc_sec_parms = encrypt_gpg_sec_parms(sec_str, passphrase, salt, iv, sizeof(iv));

    struct sshbuf * seckey = sshbuf_new();
    sshbuf_putf(seckey, "(21:protected-private-key(3:ecc");
    sshbuf_putb(seckey, pub_parms);
    sshbuf_put(seckey, GPG_SEC_PARM_PREFIX, strlen(GPG_SEC_PARM_PREFIX));
    sshbuf_put(seckey, salt, sizeof(salt));
    sshbuf_putf(seckey, "8:%08d)%d:", S2K_ITER_BYTE_COUNT, (int) sizeof(iv));
    sshbuf_put(seckey, iv, sizeof(iv));
    sshbuf_putf(seckey, ")%lu:", sshbuf_len(enc_sec_parms));
    sshbuf_put(seckey, sshbuf_ptr(enc_sec_parms), sshbuf_len(enc_sec_parms));
    sshbuf_put_u8(seckey, ')');
    sshbuf_put(seckey, protected_at, strlen(protected_at));
    sshbuf_put_u8(seckey, ')');
    sshbuf_put_u8(seckey, ')');

    sshbuf_free(pub_parms);
    sshbuf_free(sec_parms);
    sshbuf_free(hash_str);
    sshbuf_free(sec_str);
    sshbuf_free(enc_sec_parms);
    return seckey;
}

/**
 *  Generate random symmetric key, wrap in frame
 *
 *  We are going to encrypt file data using AES-256 in cipher feedback (CFB) mode. We need to generate a
 *  random AES256 key, then put it into the "frame" that will actually be encrypted using the public key
 *  algorithm. Since we are using curve25519, a variant of ECDH, the frame is just the symmetric key
 *  algorithm followed by the key value followed by a two-byte checksum of the key. This frame is then
 *  padded out to a multiple of eight bytes, which means adding n bytes of n to the end. (For our case,
 *  n will be 5).
 *
 *  @param sym_key_frame Place to write generated frame. Should point to at least AES256_KEY_BYTES +
 *                       AES_WRAP_BLOCK_SIZE bytes
 *  @return int number of bytes in generated frame
 */
int
generate_gpg_sym_key_frame(u_char * sym_key_frame)
{
    u_char * frame_ptr = sym_key_frame;
    *(frame_ptr++) = GPG_SKALGO_AES256;
    randombytes_buf(frame_ptr, AES256_KEY_BYTES);

    unsigned short cksum = 0;
    int i;
    for (i = 1; i <= AES256_KEY_BYTES; i++) {
        cksum += *(frame_ptr++);
    }
    *(frame_ptr++) = (cksum >> 8);
    *(frame_ptr++) = cksum;

    //  Need to buffer to full AES_WRAP_BLOCK_SIZE block. Padding byte value is just the number of bytes
    //  of padding required. (Don't blame me, not my choice.)
    int num_to_pad = AES_WRAP_BLOCK_SIZE - (frame_ptr - sym_key_frame) % AES_WRAP_BLOCK_SIZE;
    if (num_to_pad != AES_WRAP_BLOCK_SIZE) {
        for (i = 0; i < num_to_pad; i++) {
            *(frame_ptr++) = num_to_pad;
        }
    }

    return (frame_ptr - sym_key_frame);
}

/**
 *  Encrypt a generated key frame.
 *
 *  Use OpenSSL crypto routines to encrypt the key frame using the generated KEK. This is done with
 *  AES128 in "key wrap" mode. We need to use the OpenSSL EVP API instead of the OpenSSH wrapper,
 *  because OpenSSH doesn't recognize aes128-wrap.
 *
 *  @param sym_key_frame Generated frame containing symmetric key
 *  @param frame_len Num bytes in sym_key_frame
 *  @param key struct containing recipient's public key info
 *  @param enc_frame Place to write encrypted frame (at least AES256_KEY_BYTES + 2 * AES_WRAP_BLOCK_SIZE bytes)
 *  @param ephem_pk Place to write the ephemeral public key required to decrypt (at least
 *                  crypto_box_PUBLICKEYBYTES + 1 bytes)
 *  @return int Num bytes in enc_frame, or negative number if error
 */
int
encrypt_gpg_key_frame(const u_char * sym_key_frame, int frame_len, const gpg_public_key * key,
                      u_char * enc_frame, u_char * ephem_pk)
{
    u_char secret[crypto_box_BEFORENMBYTES];
    generate_curve25519_ephem_shared_secret(key->key, ephem_pk + 1, secret);
    ephem_pk[0] = GPG_ECC_PUBKEY_PREFIX;            //  Indicates that it is on the X value, not the complete point

    u_char kek[AES128_KEY_BYTES];
    generate_gpg_kek(key->fp, secret, kek);

    EVP_CIPHER_CTX ciphctx;
    const EVP_CIPHER * cipher = EVP_aes_128_wrap();

    int written = -1;

    EVP_CIPHER_CTX_init(&ciphctx);
    EVP_CIPHER_CTX_set_flags(&ciphctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if (EVP_EncryptInit_ex(&ciphctx, cipher, NULL /* dflt engine */, kek, NULL /* dflt iv */)) {
        if (EVP_EncryptUpdate(&ciphctx, enc_frame, &written, sym_key_frame, frame_len)) {
            int tmp_written;
            if (EVP_EncryptFinal_ex(&ciphctx, enc_frame + written, &tmp_written)) {
                written += tmp_written;
            }
        }
    }
    EVP_CIPHER_CTX_cleanup(&ciphctx);
    return written;
}

