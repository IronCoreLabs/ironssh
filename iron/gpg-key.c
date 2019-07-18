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
#include "xmalloc.h"

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

#define GPG_CV_PUB_PARM_PREFIX  "(5:curve10:Curve25519)(5:flags9:djb-tweak)(1:q"
#define GPG_ED_PUB_PARM_PREFIX  "(5:curve7:Ed25519)(5:flags5:eddsa)(1:q"
#define GPG_SEC_PARM_PREFIX     "(9:protected25:openpgp-s2k3-sha1-aes-cbc((4:sha18:"

#define PROTECTED_AT_LEN        36      //  # chars in (12:protected-at15:<date>) string (w/ null terminator)

/*  Curve 25519 parameters P, A, B, N, G_X, G_Y, H)
       y^2 = x^3 + 48662 x^2 + x
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

typedef struct curve_param_entry {
    char param_name;
    u_char * value;
    int len;
} curve_param_entry;

curve_param_entry curve25519_param[] = {
    { 'p', curve25519_p, sizeof(curve25519_p) },
    { 'a', curve25519_a, sizeof(curve25519_a) },
    { 'b', curve25519_b, sizeof(curve25519_b) },
    { 'g', curve25519_g, sizeof(curve25519_g) },
    { 'n', curve25519_n, sizeof(curve25519_n) }
};


/*  Ed25519 parameters P, A, B, N, G_X, G_Y, H)
       -x^2 + y^2 = 1 + dx^2y^2
    P   = "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED",     prime
    A   = "-0x01",                                                                  A coefficient of curve
    B   = "-0x2DFC9311D490018C7338BF8688861767FF8FF5B2BEBE27548A14B235ECA6874A",    B coefficient of curve
    N   = "0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED",     order of base point
    G_X = "0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A",     base point X
    G_Y = "0x6666666666666666666666666666666666666666666666666666666666666658",     base point Y
    H   = "0x08"                                                                    cofactor
*/

static u_char ed25519_a[] = {
    0x01
};
static u_char ed25519_b[] = {
    0x2d, 0xfc, 0x93, 0x11, 0xd4, 0x90, 0x01, 0x8c, 0x73, 0x38, 0xbf, 0x86, 0x88, 0x86, 0x17, 0x67,
    0xff, 0x8f, 0xf5, 0xb2, 0xbe, 0xbe, 0x27, 0x54, 0x8a, 0x14, 0xb2, 0x35, 0xec, 0xa6, 0x87, 0x4a
};
static u_char ed25519_g[] = {
    0x04,
    0x21, 0x69, 0x36, 0xd3, 0xcd, 0x6e, 0x53, 0xfe, 0xc0, 0xa4, 0xe2, 0x31, 0xfd, 0xd6, 0xdc, 0x5c,
    0x69, 0x2c, 0xc7, 0x60, 0x95, 0x25, 0xa7, 0xb2, 0xc9, 0x56, 0x2d, 0x60, 0x8f, 0x25, 0xd5, 0x1a,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x58
};

/*  The OID for Ed25519 in OpenPGP format. This represents the text OID 1.3.6.1.4.1.11591.15.1  */
static const char ed25519_oid[] = {
    0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01
};

curve_param_entry ed25519_param[] = {
    { 'p', curve25519_p, sizeof(curve25519_p) },
    { 'a', ed25519_a,    sizeof(ed25519_a) },
    { 'b', ed25519_b,    sizeof(ed25519_b) },
    { 'g', ed25519_g,    sizeof(ed25519_g) },
    { 'n', curve25519_n, sizeof(curve25519_n) }
};

#define GPG_KEY_PKT_PKALGO_OFFSET    5     //  # bytes at start of key/subkey packet body before algo type

//  Version, 4-byte timestamp, algo, 10-byte OID, 2-byte MPI length, 32-byte MPI
#define GPG_ED25519_PUBKEY_PKT_LEN   (8 + sizeof(ed25519_oid) + crypto_sign_PUBLICKEYBYTES)

//  Version, 4-byte timestamp, algo, 11-byte OID, 2-byte MPI length, 32-byte MPI
#define GPG_CV25519_PUBKEY_PKT_LEN   (8 + sizeof(curve25519_oid) + crypto_box_PUBLICKEYBYTES)


/**
 *  Write byte array containing Elliptic Curve point's X coordinate to buffer as S-expression
 *
 *  Format an array of bytes as a GPG S-expression (length in bytes, as an ASCII string, followed by ':',
 *  then the byte array). But add a '@' character (0x40) before the value to indicate that it is only the
 *  X coordinate, not a complete (X, Y) point.
 *
 *  @param buf Place to write S-expression
 *  @param x_coord X coordinate to write
 *  @param len Num bytes in x_coord
 */
static void
put_x_coord_sexpr(struct sshbuf * buf, const u_char * x_coord, int len)
{
    char tmp[16];
    sprintf(tmp, "%d:", len + 1);      //  For the extra '@'
    sshbuf_put(buf, tmp, strlen(tmp));
    sshbuf_put_u8(buf, GPG_ECC_PUBKEY_PREFIX);
    sshbuf_put(buf, x_coord, len);
}

/**
 *  Check whether the body of a packet is an ed25519 key
 *
 *  Look at the start of the packet body (a public or secret key or subkey) and verify that it is a
 *  ed25519 key packet.
 *
 *  @param buf byte array holding packet body
 *  @param buf_len num bytes in buf
 *  return int 1 if ed25519 key, 0 otherwise
 */
int
gpg_packet_is_ed25519_key(const u_char * buf, int buf_len)
{

    if (buf_len < (int) (GPG_KEY_PKT_PKALGO_OFFSET + 1 + sizeof(ed25519_oid)) ||
        buf[GPG_KEY_PKT_PKALGO_OFFSET] != GPG_PKALGO_ECDSA ||
        memcmp(buf + GPG_KEY_PKT_PKALGO_OFFSET + 1, ed25519_oid, sizeof(ed25519_oid)) != 0) {
        return 0;
    } else {
        return 1;
    }
}

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
    if (buf_len < (int) (GPG_KEY_PKT_PKALGO_OFFSET + 1 + sizeof(curve25519_oid)) ||
        buf[GPG_KEY_PKT_PKALGO_OFFSET] != GPG_PKALGO_ECDH ||
        memcmp(buf + GPG_KEY_PKT_PKALGO_OFFSET + 1, curve25519_oid, sizeof(curve25519_oid)) != 0) {
        return 0;
    } else {
        return 1;
    }
}

/**
 *  Do cv25519 "clamp" operation then reverse key byte array.
 *
 *  Deep in the bowels of the LibSodium operations to multiply a point by a scalar, the scalar multiplier
 *  (which is the secret key) is "clamped" before multiplying the point by it. In GPG, this clamping is not
 *  automatically done on the multiplication operation, so we will go ahead and clamp the secret key here.
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
 *  Generate GPG keygrip for an ed25519 or curve25519 key.
 *
 *  The GPG keygrip is a shortened representation (i.e. hash) of the parameters of the public key. The hash
 *  is just SHA1.
 *
 *  @param pub_key public key
 *  @param key_len Num bytes in pub_key
 *  @param grip Place to write keygrip. At least SHA_DIGEST_LENGTH bytes.
 */
static void
generate_ecc_keygrip(const curve_param_entry * params, int num_params, const u_char * pub_key, int key_len,
        u_char * grip)
{
    struct sshbuf * b = sshbuf_new();
    char buf[32];
    const curve_param_entry * ptr = params;
    int len;

    for (int ct = 0; ct < num_params; ct++) {
        len = snprintf(buf, sizeof(buf), "(1:%c%u:", ptr->param_name, ptr->len);
        sshbuf_put(b, buf, len);
        sshbuf_put(b, ptr->value, ptr->len);
        sshbuf_put_u8(b, ')');
        ptr++;
    }

    //  Can't use iron_put_num_sexpr here, because in this context, GPG doesn't add the preceding 00 octet if the
    //  high bit of the first octet is set. Thanks for the consistency, GPG.
    //iron_put_num_sexpr(b, q, q_len);
    sshbuf_putf(b, "(1:q%d:", key_len);
    sshbuf_put(b, pub_key, key_len);
    sshbuf_put_u8(b, ')');
    iron_compute_sha1_hash_sshbuf(b, grip);
    sshbuf_free(b);
}

/**
 *  Generate GPG keygrip for ed25519 key.
 *
 *  The GPG keygrip is a shortened representation (i.e. hash) of the parameters of the public key. The hash
 *  is just SHA1.
 *
 *  @param pub_key Ed25519 public key (crypto_sign_PUBLICKEYBYTES)
 *  @param grip Place to write keygrip. At least SHA_DIGEST_LENGTH bytes.
 */
void
generate_gpg_ed25519_keygrip(const u_char * pub_key, u_char * grip)
{
    generate_ecc_keygrip(ed25519_param, sizeof(ed25519_param) / sizeof(curve_param_entry),
            pub_key, crypto_sign_PUBLICKEYBYTES, grip);
}

/**
 *  Generate GPG keygrip for curve25519 key.
 *
 *  The GPG keygrip is a shortened representation (i.e. hash) of the parameters of the public key. The hash
 *  is just SHA1.
 *
 *  @param pub_key Curve25519 public key (crypto_box_PUBLICKEYBYTES)
 *  @param grip Place to write keygrip. At least SHA_DIGEST_LENGTH bytes.
 */
void
generate_gpg_curve25519_keygrip(const u_char * pub_key, u_char * grip)
{
    generate_ecc_keygrip(curve25519_param, sizeof(curve25519_param) / sizeof(curve_param_entry), pub_key,
            crypto_box_PUBLICKEYBYTES, grip);
}

/**
 *  Compute String-to-Key (s2k) key from passphrase
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
    u_char * salted_passphrase = xmalloc(len);

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
 *  Create a passphrase by signing pub key fingerprint
 *
 *  If the SSH key type is RSA or Ed25519, then the signature for a given keypair and input is deterministic.
 *  We will take advantage of that and the fact that ssh-agent caches private key info and computes signatures.
 *  Compute the fingerprint of the SSH public key then attempt to sign it. This should send a request to the
 *  ssh-agent, and if the agent isn't available or doesn't have the SSH key cached, should prompt the user for
 *  the passphrase. The signature is as long as the SSH key, which could be very long. We take the first 32
 *  bytes of the signature and base64 encode them to form the passphrase.
 *
 *  @param pub_key public SSH key parameters (should be either RSA or Ed25519)
 *  @param passphrase place to put generated passphrase (at least PPHRASE_LEN bytes)
 *  @return int 0 if successful, negative number if error
 */
static int
generate_passphrase_by_signature(const Key * pub_key, char * passphrase)
{
    int retval = -1;
    u_char * fp;
    size_t   fp_len;

    if (pub_key->type == KEY_RSA) {
        //  For RSA keys, we need to generate the "fingerprint" using the same data the previous version of the
        //  program used, so we can come up with the same passphrase and thus decrypt files that were encrypted
        //  with the previous version.
        fp_len = BN_num_bytes(pub_key->rsa->n) + BN_num_bytes(pub_key->rsa->e);
        fp = xmalloc(fp_len);
        u_char * t_ptr = fp;
        t_ptr += BN_bn2bin(pub_key->rsa->n, t_ptr);
        t_ptr += BN_bn2bin(pub_key->rsa->e, t_ptr);
    } else if (sshkey_fingerprint_raw(pub_key, SSH_DIGEST_SHA1, &fp, &fp_len) != 0) {
        error("Unable to compute fingerprint for SSH key.");
        return -1;
    }

    //  Ask the agent to sign the fingerprint. (It will actually compute a hash and sign that.)
    //  If the agent isn't running, retrieve the private key and sign the params in process (will prompt
    //  for passphrase for secret SSH key).
    u_char * signature = NULL;
    size_t   sig_len;
    int      agent_fd;

    if (ssh_get_authentication_socket(&agent_fd) == 0) {
        //  Specify NULL for the hash algorithm - for RSA keys, this defaults to "ssh-rsa", which is SHA1. That's
        //  fine, since several versions of ssh-agent seem to ignore "rsa-sha2-256" and just pick "ssh-rsa" anyway.
        if (ssh_agent_sign(agent_fd, (Key *) pub_key, &signature, &sig_len, fp, fp_len, NULL, 0) != 0) {
            signature = NULL;
        }
    }

    if (signature == NULL) {
        //  No authentication agent, or the authentication agent didn't have the secret key, means we
        //  need user's private key to sign the hash - need to fetch them from the user's private key file.
        Key * sec_key = NULL;
        int rv = get_ssh_private_key(&sec_key);
        if (rv != 0) {
            error("Unable to retrieve private SSH key: %s", ssh_err(rv));
            retval = -2;
            sec_key = NULL;
        }

        if (sec_key != NULL) {
            int rv = sshkey_sign(sec_key, &signature, &sig_len, fp, fp_len, NULL, 0);
            if (rv != 0) {
                error("Error generating signature for passphrase - %s.", ssh_err(rv));
                retval = -4;
            }
            sshkey_free(sec_key);
        }
    }

    if (signature != NULL) {
        //  The signature has a four byte lenth (MSB first), a string identifying the signing algorithm, another
        //  four byte length, and the signature. Find the meaty signature bits.
        u_char * sptr = signature;
        u_int32_t len = iron_buf_to_int(sptr);
        sptr += 4 + len;
        len = iron_buf_to_int(sptr);
        sptr += 4;
        if ((sig_len - len) != (size_t) (sptr - signature)) {
            error("Unrecognized format for SSH signature. Unable to generate passphrase.");
            retval = -5;
        } else {
            uuencode(sptr, PRE_ENC_PPHRASE_BYTES, passphrase, PPHRASE_LEN);
            retval = 0;
        }
        free(signature);
    }
    free(fp);

    return retval;
}

/**
 *  Create a passphrase by hashing secret key
 *
 *  If the SSH key type is DSA or ECDSA, then the signature for a given keypair and input is non-deterministic,
 *  so we can't use the trick we did with RSA and Ed25519 keys to generate a passphrase. Instead, we grab the
 *  private key (which can't use the ssh-agent, even if it's configured and has the key cached) - so the user will
 *  need to enter the SSH key passphrase once each session. Once we get the private key, repeatedly hash it, then
 *  base64 encode the first 32 bytes of the hash to form the passphrase.
 *
 *  @param pub_key public SSH key parameters (should be either DSA or ECDSA)
 *  @param passphrase place to put generated passphrase (at least PPHRASE_LEN bytes)
 *  @return int 0 if successful, negative number if error
 */
static int
generate_passphrase_by_hash(char * passphrase)
{
    Key * sec_key = NULL;
    int retval = get_ssh_private_key(&sec_key);
    if (retval == 0) {
        const BIGNUM * priv_key;

        if (sec_key->dsa != NULL) priv_key = sec_key->dsa->priv_key;
        else if (sec_key->ecdsa != NULL) priv_key = EC_KEY_get0_private_key(sec_key->ecdsa);
        else {
            error("SSH key was not either DSA or ECDSA.");
            retval = -2;
        }

        if (retval == 0) {
            //  We will hash the private key A LOT to generate the final value - assuming the key is 32 bytes,
            //  hashing it 32768 times runs 1MB through the hash.
            int len = BN_num_bytes(priv_key);
            u_char * hash_str = xmalloc(len);
            BN_bn2bin(priv_key, hash_str);
            SHA256_CTX ctx;
            SHA256_Init(&ctx);
            for (int i = 0; i < 32768; i++) SHA256_Update(&ctx, hash_str, len);
            u_char hash[PRE_ENC_PPHRASE_BYTES];
            bzero(hash, sizeof(hash));
            SHA256_Final(hash, &ctx);
            uuencode(hash, sizeof(hash), passphrase, PPHRASE_LEN);
        }
    } else {
        error("Unable to retrieve private SSH key: %s", ssh_err(retval));
    }

    return retval;
}

/**
 *  Create a passphrase to secure secret keys
 *
 *  Generate a text passphrase to secure the GPG secret keys. We only want to allow access to the GPG keys
 *  if the user has access to an SSH key. We grab the public SSH key from ~/.ssh/ironcore/id_iron.pub and
 *  compute a passphrase from that based on the type of key.
 *
 *  @param passphrase place to put generated passphrase (at least PPHRASE_LEN bytes)
 *  @returns int 0 if successful, negative number if error
 */
int
generate_gpg_passphrase(char * passphrase)
{
    static char   cached_passphrase[PPHRASE_LEN] = { '\0' };

    if (*cached_passphrase != '\0') {
        strcpy(passphrase, cached_passphrase);
        return 0;
    }

    int retval = -1;
    Key * pub_key;
    if (get_ssh_public_key(&pub_key) != 0) {
        return -1;
    }

    if (pub_key->rsa != NULL || pub_key->ed25519_pk != NULL) {
        retval = generate_passphrase_by_signature(pub_key, passphrase);
    } else {
        retval = generate_passphrase_by_hash(passphrase);
    }

    if (retval == 0) strcpy(cached_passphrase, passphrase);
    sshkey_free(pub_key);

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
 *  Generate the public parameters for an Ed25519 or Cv25519 key
 *
 *  Format the public parms into an sshbuf that can be written to a public key file.
 *
 *  @param oid OID string identifying type of curve
 *  @param oid_len num bytes in oid
 *  @param pub_key key value to write
 *  @param pk_len num bytes in pub_key
 *  @param buf place to write the generated params
 */
static void
generate_ecc_pubkey_parms(const char * oid, int oid_len, const u_char * pub_key, int pk_len, struct sshbuf * buf)
{
    sshbuf_put(buf, oid, oid_len);

    /* A bit more GPG/libgcrypt fun - the public key parameter q needs to be prefixed by an octet that indicates
     * that it is only the x coordinate. However, we need the unprefixed key for other uses, so we need to remember
     * to add the prefix only in the necessary spots. Bad GPG! Anyway, create a separate copy of the parameter that
     * includes the prefix to put into the public subkey packet.
     */
    u_char prefixed_pk[crypto_sign_PUBLICKEYBYTES + 1];
    prefixed_pk[0] = GPG_ECC_PUBKEY_PREFIX;
    memcpy(prefixed_pk + 1, pub_key, pk_len);
    BIGNUM * pk = BN_new();
    BN_bin2bn(prefixed_pk, pk_len + 1, pk);
    iron_put_bignum(buf, pk);
    BN_clear_free(pk);
}

/**
 *  Generate the public parameters for an Ed25519 key
 *
 *  Format the public parms into an sshbuf that can be written to a public key file.
 *
 *  @param pub_key key value to write
 *  @param pk_len num bytes in pub_key
 *  @param buf place to write the generated params
 */
void
generate_gpg_ed25519_pubkey_parms(const u_char * pub_key, struct sshbuf * buf)
{
    generate_ecc_pubkey_parms(ed25519_oid, sizeof(ed25519_oid), pub_key, crypto_sign_PUBLICKEYBYTES, buf);
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
generate_gpg_curve25519_pubkey_parms(const u_char * pub_key, struct sshbuf * buf)
{
    generate_ecc_pubkey_parms(curve25519_oid, sizeof(curve25519_oid), pub_key, crypto_box_PUBLICKEYBYTES, buf);

    //  The last parameter specifies the hash algorithm and the encryption algorithm used to derive the key
    //  encryption key (KEK).
    sshbuf_put(buf, curve25519_kek_parm, sizeof(curve25519_kek_parm));
}

/**
 *  Recover ed25519 public key from pubkey packet body
 *
 *  @param buf Pubkey packet body
 *  @param key Place to write recovered ed25519 public key (at least crypto_sign_PUBLICKEYBYTES)
 *  @return int num bytes written to key if successful, negative number if error
 */
int
extract_gpg_ed25519_pubkey(const struct sshbuf * buf, u_char * key)
{
    int key_len = -1;

    if (sshbuf_len(buf) >= GPG_ED25519_PUBKEY_PKT_LEN) {
        const u_char * key_ptr = sshbuf_ptr(buf) + GPG_KEY_PKT_PKALGO_OFFSET + 1 + sizeof(ed25519_oid);
        key_len = (*key_ptr << 8) + *(key_ptr + 1);
        //  Size in bits from the header of the MPI - convert to bytes, then deduct leading 0x40
        key_len = (key_len + 7) / 8 - 1;
        key_ptr += 2;
        if (*(key_ptr++) == GPG_ECC_PUBKEY_PREFIX) {
            memcpy(key, key_ptr, key_len);
        } else {
            error("Invalid format for public signing key - could not recover data.");
            key_len = -1;
        }
    } else {
        error("Data in public key packet too short. Unable to retrieve key.");
    }

    return key_len;
}

/**
 *  Recover curve25519 public key from pubkey packet body
 *
 *  @param buf Pubkey packet body
 *  @param key Place to write recovered curve25519 public key (at least crypto_box_PUBLICKEYBYTES)
 *  @return int num bytes written to key if successful, negative number if error
 */
int
extract_gpg_curve25519_pubkey(const struct sshbuf * buf, u_char * key)
{
    int key_len = -1;

    if (sshbuf_len(buf) >= GPG_CV25519_PUBKEY_PKT_LEN) {
        const u_char * key_ptr = sshbuf_ptr(buf) + GPG_KEY_PKT_PKALGO_OFFSET + 1 + sizeof(curve25519_oid);
        key_len = (*key_ptr << 8) + *(key_ptr + 1);
        //  Size in bits from the header of the MPI - convert to bytes, then deduct leading 0x40
        key_len = (key_len + 7) / 8 - 1;
        key_ptr += 2;
        if (*(key_ptr++) == GPG_ECC_PUBKEY_PREFIX) {
            memcpy(key, key_ptr, key_len);
        } else {
            error("Invalid format for public encryption key - could not recover data.");
            key_len = -1;
        }
    } else {
        error("Data in public key packet too short. Unable to retrieve key.");
    }

    return key_len;
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
        u_char * input = xmalloc(sshbuf_len(buf) + AES128_KEY_BYTES);
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

    generate_gpg_kek(pub_keys->enc_fp, secret, kek);
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
decrypt_gpg_sec_parms(const u_char * enc_data, int len, const u_char * salt, int hash_bytes, const u_char * iv)
{
    char * output = NULL;

    //  First, generate the passphrase from the RSA key and generate the symmetric key from that.
    u_char sym_key[AES128_KEY_BYTES];
    char   passphrase[PPHRASE_LEN];

    if (generate_gpg_passphrase(passphrase) == 0) {
        compute_gpg_s2k_key(passphrase, sizeof(sym_key), salt, hash_bytes, sym_key);

        struct sshcipher_ctx ciphercontext;
        const struct sshcipher * cipher = cipher_by_name("aes128-cbc");
        if (cipher_init(&ciphercontext, cipher, sym_key, sizeof(sym_key), iv, GPG_SECKEY_IV_BYTES,
                        CIPHER_DECRYPT) == 0) {
            output = xmalloc(len);
            if (output != NULL) {
                if (cipher_crypt(&ciphercontext, 0, output, enc_data, len, 0, 0) != 0) {
                    error("Decryption of RSA private key failed.");
                    free(output);
                    output = NULL;
                }
            }
        } else {
            error("Failed to initialize to decrypt RSA private key.");
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
 *  @param pub_parm_name Name of the preceding public parameter in S-Expr ('n' for RSA, 'q' for ed/cv25519)
 *  @param key_name Name of the algorithm corresponding to the key (for error msgs)
 *  @param buf Byte array containing S-expression
 *  @param buf_len Num bytes in buf
 *  @param ssh_key SSH key used to protect GPG key
 *  @return u_char * S-expression containing parms, or NULL if error. Caller should free
 */
static u_char *
extract_gpg_sec_parms(char pub_parm_name, const char * key_name, const u_char * buf, int buf_len)
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
        sec_parms = decrypt_gpg_sec_parms(ptr, len, salt, hash_bytes, iv);

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
 *  Retrieve ed/cv25519 secret key param value
 *
 *  After an S-expression has been decrypted, recover the secret key value.
 *
 *  @param sec_parms S-expression containing secret ekey
 *  @param sec_key Place to write secret key value (at least key_len bytes)
 *  @param key_len Expected length of secret key
 *  @returns 0 if successful, negative number if error
 */
static int
extract_ecc_seckey(const u_char * sec_parms, u_char * sec_key, int key_len)
{
    int retval = -1;

    if (strncmp(sec_parms, "(1:d", 4) == 0) {
        const u_char * ptr = sec_parms + 4;
        errno = 0;
        int len = (int) strtoul(ptr, (char **) &ptr, 10);
        if (errno != EINVAL && errno != ERANGE && len <= (key_len + 2) && *(ptr++) == ':') {
            int pad_len = key_len - len;
            if (pad_len > 0) {
                memset(sec_key, 0, pad_len);
            } else if (pad_len < 0) {
                //  Leading 0 byte on secret key - skip it
                ptr -= pad_len;
                len += pad_len;
                pad_len = 0;
            }

            memcpy(sec_key + pad_len, ptr, len);
            retval = len;
        } else {
            error("Improperly formatted data in decrypted secret key - unable to process.");
        }
    } else {
        error("Improperly formatted data in decrypted secret key - unable to process.");
    }

    return retval;
}

/**
 *  Recover ed25519 secret key from S-expression
 *
 *  Finds the part of the S-expression containing the secret key, decrypts it, and recovers the key.
 *
 *  @param buf Byte array containing S-expression
 *  @param buf_len Num bytes in buf
 *  @parma pub_key Public ed25519 key corresponding to secret key
 *  @param sec_key Place to write secret key (at least crypto_sign_SECRETKEYBYTES)
 *  @return int Num bytes written to sec_key, negative number if error
 */
int
extract_gpg_ed25519_seckey(const u_char * buf, int buf_len, const u_char * pub_key, u_char * sec_key)
{
    int retval = -1;

    //  Need to find the start of the secret key params in the S-expression. Complicated by the fact
    //  that the public key might contain binary data, so we need to skip over it to find the secret
    //  key. We do rely on the fact that the first 'q' in the string should be the start of the public
    //  key, and everything before that is ASCII.
    u_char * sec_parms = extract_gpg_sec_parms('q', "Ed25519", buf, buf_len);
    if (sec_parms != NULL) {
        //  After we found that, the Ed25519 secret key params include ANOTHER copy of the public key,
        //  so we need to skip that again.
        u_char * ptr = memchr(sec_parms, 'q', buf_len - (sec_parms - buf));
        if (ptr != NULL) {
            ptr++;
            errno = 0;
            int len = strtol(ptr, (char **) &ptr, 10);
            ptr++;  // Skip ':'
            if (errno == EINVAL || errno == ERANGE || len <= 0 || len > GPG_MAX_KEY_SIZE) return -1;
            ptr += len;

            if (*(ptr++) != ')') return -1;
            //  And now, we have finally reached the 'd' parameter. However, this is only half of the
            //  Ed25519 secret key - the second half is ANOTHER copy of the public key. So grab the 
            //  first half, then paste in the public key to complete the puzzle.
            retval = extract_ecc_seckey(ptr, sec_key, crypto_sign_PUBLICKEYBYTES);
            if (retval > 0) {
                memcpy(sec_key + retval, pub_key, crypto_sign_PUBLICKEYBYTES);
                retval += crypto_sign_PUBLICKEYBYTES;
            }
        }
        free(sec_parms);
    }

    return retval;
}

/**
 *  Recover cv25519 secret key from S-expression
 *
 *  Finds the part of the S-expression containing the secret key, decrypts it, and recovers the key.
 *
 *  @param buf Byte array containing S-expression
 *  @param ssh_key SSH key used to protect GPG key
 *  @param sec_key Place to write secret key (at least crypto_box_SECRETKEYBYTES)
 *  @return int Num bytes written to sec_key, negative number if error
 */
int
extract_gpg_curve25519_seckey(const u_char * buf, int buf_len, u_char * sec_key)
{
    int retval = -1;

    //  Need to find the start of the secret key params in the S-expression. Complicated by the fact
    //  that the public key might contain binary data, so we need to skip over it to find the secret
    //  key. We do rely on the fact that the first 'q' in the string should be the start of the public
    //  key, and everything before that is ASCII.
    u_char * sec_parms = extract_gpg_sec_parms('q', "Curve25519", buf, buf_len);
    if (sec_parms != NULL) {
        //  Skip over "((" at start of private key portion.
        retval = extract_ecc_seckey(sec_parms + 2, sec_key, crypto_box_SECRETKEYBYTES);
        free(sec_parms);
    }

    return retval;
}

/**
 *  Generate S-expression for Ed25519 or Cv25519 public key parameter.
 *
 *  @param pub_key Ed25519 or Cv25519 public key
 *  @param pub_key_len num bytes in pub_key
 *  @param prefix string to insert as start of S-expression 
 *  @return sshbuf * S-expression. Caller should sshbuf_free
 */
static struct sshbuf *
generate_gpg_ecc_pub_parms(const u_char * pub_key, int pub_key_len, const char * prefix)
{
    /* A bit more GPG/libgcrypt fun - the public key parameter q needs to be prefixed by an octet that indicates
     * that it is only the x coordinate. However, we don't do this when generating the keygrip for the key. Bad
     * GPG! Anyway, create a separate copy of the parameter that includes the prefix and use that in the appropriate
     * places.
     */
    struct sshbuf * pub_parms = sshbuf_new();
    sshbuf_put(pub_parms, prefix, strlen(prefix));
    put_x_coord_sexpr(pub_parms, pub_key, pub_key_len);
    sshbuf_put_u8(pub_parms, ')');

    return pub_parms;
}

/**
 *  Generate S-expression for Ed25519 public key parameter.
 *
 *  @param pub_key Ed25519 public key (crypto_sign_PUBLICKEYBYTES + 1)
 *  @return sshbuf * S-expression. Caller should sshbuf_free
 */
static struct sshbuf *
generate_gpg_ed25519_pub_parms(const u_char * pub_key)
{
    return generate_gpg_ecc_pub_parms(pub_key, crypto_sign_PUBLICKEYBYTES, GPG_ED_PUB_PARM_PREFIX);
}

/**
 *  Generate S-expression for Cv25519 public key parameter.
 *
 *  @param pub_key Curve25519 public key (crypto_box_PUBLICKEYBYTES + 1)
 *  @return sshbuf * S-expression. Caller should sshbuf_free
 */
static struct sshbuf *
generate_gpg_curve25519_pub_parms(const u_char * pub_key)
{
    return generate_gpg_ecc_pub_parms(pub_key, crypto_box_PUBLICKEYBYTES, GPG_CV_PUB_PARM_PREFIX);
}

/**
 *  Generate S-expression for Ed25519 secret key parameter
 *
 *  @param pub_key Public key
 *  @param sec_key Secret key
 *  @return sshbuf * S-expression. Caller should sshbuf_free
 */
static struct sshbuf *
generate_gpg_ed25519_sec_parms(const u_char * pub_key, const u_char * sec_key)
{
    struct sshbuf * sec_parms = generate_gpg_ecc_pub_parms(pub_key, crypto_sign_PUBLICKEYBYTES, "(1:q");
    sshbuf_put(sec_parms, "(1:d", 4);
    //  Only the first half of the secret key is the "d" value. The second half is the public key value.
    //  Don't ask me why.
    iron_put_num_sexpr(sec_parms, sec_key, crypto_sign_PUBLICKEYBYTES);
    sshbuf_put_u8(sec_parms, ')');

    return sec_parms;
}

/**
 *  Generate S-expression for Cv25519 secret key parameter
 *
 *  @param sec_key Secret key
 *  @return sshbuf * S-expression. Caller should sshbuf_free
 */
static struct sshbuf *
generate_gpg_curve25519_sec_parms(const u_char * sec_key)
{
    struct sshbuf * sec_parms = sshbuf_new();
    sshbuf_put(sec_parms, "(1:d", 4);
    iron_put_num_sexpr(sec_parms, sec_key, crypto_box_SECRETKEYBYTES);
    sshbuf_put_u8(sec_parms, ')');

    return sec_parms;
}

/**
 *  Generate S-expression containing ed25519 or cv25519 key (public and secret parts)
 *
 *  Formats the GPG S-expression that holds an entire key pair. The secret key is encrypted.
 *
 *  @param pub_key Byte array containing public key (crypto_sign_PUBLICKEYBYTES)
 *  @param sec_key Byte array containing secret key (crypto_sign_SECRETKEYBYTES)
 *  @param passphrase ASCII string used to generate key to encrypt secret key
 *  @return sshbuf * Buffer containing S-expression. Caller should sshbuf_free
 */
struct sshbuf *
generate_gpg_ecc_seckey(const struct sshbuf * pub_parms, const struct sshbuf * sec_parms, const u_char * passphrase)
{
    /* First, we need to compute the hash of the key data. The string to be hashed is unfortunately not quite
     * exactly the same format as the subsequent string to write to the key, so for now we won't worry about
     * reusing pieces and parts.
     */
    char protected_at[PROTECTED_AT_LEN];

    generate_gpg_protected_at(protected_at);

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

    sshbuf_free(hash_str);
    sshbuf_free(sec_str);
    sshbuf_free(enc_sec_parms);
    return seckey;
}

/**
 *  Generate S-expression containing ed25519 key (public and secret parts)
 *
 *  Formats the GPG S-expression that holds an entire ed25519 key pair. The secret key is encrypted.
 *
 *  @param pub_key Byte array containing public key (crypto_sign_PUBLICKEYBYTES)
 *  @param sec_key Byte array containing secret key (crypto_sign_SECRETKEYBYTES)
 *  @param passphrase ASCII string used to generate key to encrypt secret key
 *  @return sshbuf * Buffer containing S-expression. Caller should sshbuf_free
 */
struct sshbuf *
generate_gpg_ed25519_seckey(const u_char * pub_key, const u_char * sec_key, const u_char * passphrase)
{
    struct sshbuf * pub_parms = generate_gpg_ed25519_pub_parms(pub_key);
    struct sshbuf * sec_parms = generate_gpg_ed25519_sec_parms(pub_key, sec_key);
    struct sshbuf * sexpr = generate_gpg_ecc_seckey(pub_parms, sec_parms, passphrase);
    sshbuf_free(pub_parms);
    sshbuf_free(sec_parms);
    return sexpr;
}

/**
 *  Generate S-expression containing cv25519 key (public and secret parts)
 *
 *  Formats the GPG S-expression that holds an entire cv25519 key pair. The secret key is encrypted.
 *
 *  @param pub_key Byte array containing public key (crypto_box_PUBLICKEYBYTES)
 *  @param sec_key Byte array containing secret key (crypto_box_SECRETKEYBYTES)
 *  @param passphrase ASCII string used to generate key to encrypt secret key
 *  @return sshbuf * Buffer containing S-expression. Caller should sshbuf_free
 */
struct sshbuf *
generate_gpg_curve25519_seckey(const u_char * pub_key, const u_char * sec_key, const u_char * passphrase)
{
    struct sshbuf * pub_parms = generate_gpg_curve25519_pub_parms(pub_key);
    struct sshbuf * sec_parms = generate_gpg_curve25519_sec_parms(sec_key);
    struct sshbuf * sexpr = generate_gpg_ecc_seckey(pub_parms, sec_parms, passphrase);
    sshbuf_free(pub_parms);
    sshbuf_free(sec_parms);
    return sexpr;
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
    generate_curve25519_ephem_shared_secret(key->enc_key, ephem_pk + 1, secret);
    ephem_pk[0] = GPG_ECC_PUBKEY_PREFIX;            //  Indicates that it is on the X value, not the complete point

    u_char kek[AES128_KEY_BYTES];
    generate_gpg_kek(key->enc_fp, secret, kek);

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

