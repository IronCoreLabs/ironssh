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

#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <errno.h>
#include <sys/types.h>
#include "sftp-common.h"
#include "openbsd-compat/openbsd-compat.h"
#include "openssl/bn.h"
#include "authfile.h"
#include "sshkey.h"
#include "ssherr.h"
#include "cipher.h"
#include "digest.h"
#include "xmalloc.h"
#include "uuencode.h"
#include "misc.h"
#include "log.h"
#include "sodium.h"
#include "openssl/opensslconf.h"
#include "openssl/evp.h"
#include "openssl/engine.h"
#include "openssl/sha.h"
#include "openssl/ripemd.h"
#include "sodium.h"
#include "sshbuf.h"
#include "iron-gpg.h"


//  Parameters and related constants for the String-to-Key (S2K) algorithm used by GPG.
#define S2K_USAGE				254 		//  Other options are 0 or 255, but we'll always use 254
#define S2K_SPEC				3			//  Iterated + salted S2K. There are Other options, but we'll always use 3
#define S2K_ITER_BYTE_COUNT		20971520	//  # of bytes to produce by iterating S2K hash
#define S2K_ITER_ENCODED		228			//  Encoding of byte count in RVC 2440 / 4880 format

#define S2K_SALT_BYTES			8			//  # bytes of randomly generated salt to prepend to passphrase

#define GPG_IV_BYTES			8		//  # bytes of randomly generated initialization vector to prepend to
										//  data before encryption

#define GPG_SECKEY_IV_BYTES		16
#define AES_BLOCK_SIZE			16
#define AES_WRAP_BLOCK_SIZE		8

#define GPG_ECC_PUBKEY_PREFIX	0x40	//  Prepended to the public key parameter q of a elliptic curve to indicate
										//  that it uses libgcrypt's "point compression", which is the x coordinate
										//  only (y is discarded). This is always the case for curve25519, so we
										//  always prefix q with this octet.
#define GPG_MDC_PKT_LEN			22		//  Two byte tag + len, 20 byte SHA1 hash


#define GPG_SECKEY_SUBDIR		"private-keys-v1.d"

#define GPG_PUBLIC_KEY_FNAME	"pubring.gpg"
#define GPG_KEY_VERSION			4
#define GPG_PKESK_VERSION		3		//  Current version for public key encrypted session key packets
#define GPG_SEIPD_VERSION		1		//  Current version for symmetrically encrypted integrity protected data pkts


/*  Tags used to indicate the types of GPG messages.  */
typedef enum gpg_tag {
	GPG_TAG_DO_NOT_USE			= 0,
	GPG_TAG_PKESK				= 1,	//  Public-key encrypted session key
	GPG_TAG_SIGNATURE			= 2,
	GPG_TAG_SKESK				= 3,	//  Symmetric-key encrypted session key
	GPG_TAG_ONE_PASS_SIGNATURE	= 4,
	GPG_TAG_SECRET_KEY			= 5,
	GPG_TAG_PUBLIC_KEY			= 6,
	GPG_TAG_SECRET_SUBKEY		= 7,
	GPG_TAG_COMPRESSED_DATA		= 8,
	GPG_TAG_SYM_ENCRYPTED_DATA	= 9,
	GPG_TAG_MARKER				= 10,
	GPG_TAG_LITERAL_DATA		= 11,
	GPG_TAG_TRUST				= 12,
	GPG_TAG_USERID				= 13,
	GPG_TAG_PUBLIC_SUBKEY		= 14,
	GPG_TAG_USER_ATTRIBUTE		= 17,
	GPG_TAG_SEIP_DATA			= 18,	//  Symmetrically encrypted and integrity protected data
	GPG_TAG_MOD_DETECT_CODE		= 19,
	GPG_TAG_RESERVED1			= 60,	//  Reserved for private/experimental use
	GPG_TAG_RESERVED2			= 61,
	GPG_TAG_RESERVED3			= 62,
	GPG_TAG_RESERVED4			= 63
} gpg_tag;


/*  Public key encryption algorithm identifiers. The _E suffix indicates encryption-only, _S indicates signing-only,
 *  and _ES can be used for either.
 */
typedef enum gpg_pk_algo {
	GPG_PKALGO_RSA_ES			= 1,
	GPG_PKALGO_RSA_E			= 2,
	GPG_PKALGO_RSA_S			= 3,
	GPG_PKALGO_ELGAMAL_E		= 16,
	GPG_PKALGO_DSA				= 17,
	GPG_PKALGO_ECDH				= 18,
	GPG_PKALGO_ECDSA			= 19,
	GPG_PKALGO_RESERVED20		= 20, 	//  Was ELGAMAL_ES
	GPG_PKALGO_DH				= 21,	//  X9.42
	GPG_PKALGO_EDDSA			= 22,	//  EdDSA (Ed25519 support)
	GPG_PKALGO_RESERVED100		= 100,	//  Private/experimental algorithms
	GPG_PKALGO_RESERVED101		= 101,
	GPG_PKALGO_RESERVED102		= 102,
	GPG_PKALGO_RESERVED103		= 103,
	GPG_PKALGO_RESERVED104		= 104,
	GPG_PKALGO_RESERVED105		= 105,
	GPG_PKALGO_RESERVED106		= 106,
	GPG_PKALGO_RESERVED107		= 107,
	GPG_PKALGO_RESERVED108		= 108,
	GPG_PKALGO_RESERVED109		= 109,
	GPG_PKALGO_RESERVED110		= 110
} gpg_pk_algo;

/*  Symmetric key encryption algorithm identifiers.  */
typedef enum gpg_sk_algo {
	GPG_SKALGO_PLAINTEXT		= 0,
	GPG_SKALGO_IDEA				= 1,
	GPG_SKALGO_TRIPLEDES		= 2,
	GPG_SKALGO_CAST5			= 3,	//  128-bit key
	GPG_SKALGO_BLOWFISH			= 4,	//  128-bit key, 16 rounds
	GPG_SKALGO_RESERVED5		= 5,
	GPG_SKALGO_RESERVED6		= 6,
	GPG_SKALGO_AES128			= 7,
	GPG_SKALGO_AES192			= 8,
	GPG_SKALGO_AES256			= 9,
	GPG_SKALGO_TWOFISH256		= 10,
	GPG_SKALGO_CAMELLIA128		= 11,
	GPG_SKALGO_CAMELLIA192		= 12,
	GPG_SKALGO_CAMELLIA256		= 13,
	GPG_SKALGO_RESERVED100		= 100,	//  Private/experimental algorithms
	GPG_SKALGO_RESERVED101		= 101,
	GPG_SKALGO_RESERVED102		= 102,
	GPG_SKALGO_RESERVED103		= 103,
	GPG_SKALGO_RESERVED104		= 104,
	GPG_SKALGO_RESERVED105		= 105,
	GPG_SKALGO_RESERVED106		= 106,
	GPG_SKALGO_RESERVED107		= 107,
	GPG_SKALGO_RESERVED108		= 108,
	GPG_SKALGO_RESERVED109		= 109,
	GPG_SKALGO_RESERVED110		= 110
} gpg_sk_algo;

/*  Compress algorithm identifiers.  */
typedef enum gpg_compression_algo {
	GPG_COMPALGO_UNCOMP			= 0,
	GPG_COMPALGO_ZIP			= 1,
	GPG_COMPALGO_ZLIB			= 2,
	GPG_COMPALGO_BZIP			= 3,
	GPG_COMPALGO_RESERVED100	= 100,	//  Private/experimental algorithms
	GPG_COMPALGO_RESERVED101	= 101,
	GPG_COMPALGO_RESERVED102	= 102,
	GPG_COMPALGO_RESERVED103	= 103,
	GPG_COMPALGO_RESERVED104	= 104,
	GPG_COMPALGO_RESERVED105	= 105,
	GPG_COMPALGO_RESERVED106	= 106,
	GPG_COMPALGO_RESERVED107	= 107,
	GPG_COMPALGO_RESERVED108	= 108,
	GPG_COMPALGO_RESERVED109	= 109,
	GPG_COMPALGO_RESERVED110	= 110
} gpg_compression_algo;

/*  Hash algorithm identifiers.  */
typedef enum gpg_hash_algo {
	GPG_HASHALGO_MD5			= 1,
	GPG_HASHALGO_SHA1			= 2,
	GPG_HASHALGO_RIPE_MD160		= 3,
	GPG_HASHALGO_SHA256			= 8,
	GPG_HASHALGO_SHA384			= 9,
	GPG_HASHALGO_SHA512			= 10,
	GPG_HASHALGO_SHA224			= 11,
	GPG_HASHALGO_RESERVED100	= 100,	//  Private/experimental algorithms
	GPG_HASHALGO_RESERVED101	= 101,
	GPG_HASHALGO_RESERVED102	= 102,
	GPG_HASHALGO_RESERVED103	= 103,
	GPG_HASHALGO_RESERVED104	= 104,
	GPG_HASHALGO_RESERVED105	= 105,
	GPG_HASHALGO_RESERVED106	= 106,
	GPG_HASHALGO_RESERVED107	= 107,
	GPG_HASHALGO_RESERVED108	= 108,
	GPG_HASHALGO_RESERVED109	= 109,
	GPG_HASHALGO_RESERVED110	= 110
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
	GPG_SIG_SUBPKT_SIGNATURE_CREATION_TIME	= 2,		// time_t
	GPG_SIG_SUBPKT_SIGNATURE_LIFETIME		= 3,		// 4 octets - # seconds after creation
	GPG_SIG_SUBPKT_EXPORTABLE				= 4,		// boolean
	GPG_SIG_SUBPKT_TRUST					= 5,		// 1 octet level, 1 octet amount
	GPG_SIG_SUBPKT_REGEX					= 6,		// null-terminated string
	GPG_SIG_SUBPKT_REVOCABLE				= 7,		// boolean
	GPG_SIG_SUBPKT_KEY_LIFETIME				= 9,		// 4 octets - # seconds after creation
	GPG_SIG_SUBPKT_PREF_SYM_ALGO			= 11,		// list of one octet algo IDs
	GPG_SIG_SUBPKT_REVOCATION_KEY			= 12,		// 1 octet class, 1 octet PK algo, 20 octet fingerprint
	GPG_SIG_SUBPKT_ISSUER					= 16,		// 8 octet key ID
	GPG_SIG_SUBPKT_NOTATION_DATA			= 20,		// 4 octet flags, 2 octet name len, 2 octet val len,
														//   name data, val data
	GPG_SIG_SUBPKT_PREF_HASH_ALGO			= 21,		// list of one octet algo IDs
	GPG_SIG_SUBPKT_PREF_COMPRESS_ALGO		= 22,		// list of one octet algo IDs
	GPG_SIG_SUBPKT_KEY_SERVER_PREFS			= 23,		// n octets of flags
	GPG_SIG_SUBPKT_PREF_KEY_SERVER			= 24,		// URI of key server
	GPG_SIG_SUBPKT_PRIMARY_USER_ID			= 25,		// boolean
	GPG_SIG_SUBPKT_POLICY_URI				= 26,		// URI
	GPG_SIG_SUBPKT_KEY_FLAGS				= 27,		// n octets
	GPG_SIG_SUBPKT_SIGNER_USER_ID			= 28,		// 
	GPG_SIG_SUBPKT_REVOCATION_REASON		= 29,		// 
	GPG_SIG_SUBPKT_FEATURES					= 30,		// n octets of flags
	GPG_SIG_SUBPKT_SIGNATURE_TARGET			= 31,		//
	GPG_SIG_SUBPKT_EMBEDDED_SIGNATURE		= 32,		//
	GPG_SIG_SUBPKT_EXP_100					= 100,		// Experimental / private codes
	GPG_SIG_SUBPKT_EXP_101					= 101,
	GPG_SIG_SUBPKT_EXP_102					= 102,
	GPG_SIG_SUBPKT_EXP_103					= 103,
	GPG_SIG_SUBPKT_EXP_104					= 104,
	GPG_SIG_SUBPKT_EXP_105					= 105,
	GPG_SIG_SUBPKT_EXP_106					= 106,
	GPG_SIG_SUBPKT_EXP_107					= 107,
	GPG_SIG_SUBPKT_EXP_108					= 108,
	GPG_SIG_SUBPKT_EXP_109					= 109,
	GPG_SIG_SUBPKT_EXP_110					= 110
} gpg_signature_subpket_type;

/*  Wrapper for a complete GPG message - body is just stored in an sshbuf.  */
typedef struct gpg_message {
	gpg_tag			tag;
	ssize_t			len;
	struct sshbuf *	data;
} gpg_message;

#define MAX_LOGIN_LEN	32

/*  Public key and associated info for the specified login.  */
typedef struct gpg_public_key {
	char          login[MAX_LOGIN_LEN + 1];
	unsigned char key[crypto_box_PUBLICKEYBYTES];
	unsigned char fp[GPG_KEY_FP_LEN];
	unsigned char signer_fp[GPG_KEY_FP_LEN];
} gpg_public_key;


// =============================  TrustDB-related =============================

#define GPG_TRUSTDB_FNAME		"trustdb.gpg"
#define GPG_TRUSTDB_VER					3

#define GPG_TRUST_MASK      			15
#define GPG_TRUST_UNKNOWN   			0  /* o: not yet calculated/assigned */
#define GPG_TRUST_EXPIRED   			1  /* e: calculation may be invalid */
#define GPG_TRUST_UNDEFINED 			2  /* q: not enough information for calculation */
#define GPG_TRUST_NEVER     			3  /* n: never trust this pubkey */
#define GPG_TRUST_MARGINAL  			4  /* m: marginally trusted */
#define GPG_TRUST_FULLY     			5  /* f: fully trusted      */
#define GPG_TRUST_ULTIMATE  			6  /* u: ultimately trusted */
/* Trust values not covered by the mask. */
#define GPG_TRUST_FLAG_REVOKED      	32 /* r: revoked */
#define GPG_TRUST_FLAG_SUB_REVOKED  	64 /* r: revoked but for subkeys */
#define GPG_TRUST_FLAG_DISABLED     	128 /* d: key/uid disabled */


#define GPG_TRUST_RECTYPE_VER			1
#define GPG_TRUST_RECTYPE_HTBL			10
#define GPG_TRUST_RECTYPE_HLIST			11
#define GPG_TRUST_RECTYPE_TRUST			12
#define GPG_TRUST_RECTYPE_VALID			13
#define GPG_TRUST_RECTYPE_FREE			254


#define GPG_TRUST_MODEL_CLASSIC			0
#define GPG_TRUST_MODEL_PGP				1
#define GPG_TRUST_MODEL_EXTERNAL		2
#define GPG_TRUST_MODEL_ALWAYS			3
#define GPG_TRUST_MODEL_DIRECT			4
#define GPG_TRUST_MODEL_AUTO			5
#define GPG_TRUST_MODEL_TOFU			6
#define GPG_TRUST_MODEL_TOFU_PGP		7


#define GPG_TRUST_DFLT_COMPLETES		1
#define GPG_TRUST_DFLT_MARGINALS		3
#define GPG_TRUST_DFLT_CERT_DEPTH		5
#define GPG_TRUST_DFLT_MIN_CERT			2


#define GPG_TRUST_REC_SIZE				40
#define GPG_TRUST_MIN_HTBL_SIZE			256
#define GPG_TRUST_HTBL_ITEMS_PER_REC	9


#define GPG_MAX_UID_LEN			64
#define PROTECTED_AT_LEN		36		//  # chars in (12:protected-at15:<date>) string (w/ null terminator)

#define GPG_PUB_PARM_PREFIX		"(5:curve10:Curve25519)(5:flags9:djb-tweak)(1:q"
#define GPG_SEC_PARM_PREFIX		"(9:protected25:openpgp-s2k3-sha1-aes-cbc((4:sha18:"

static time_t	gpg_now;		//  Everything that timestamps a packet during the same "transaction" should
								//  use this time, so they all get timestamped the same.

/*  Curve 25519 parameters P, A, B, N, G_X, G_Y, H)
    P   = "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED",		prime
    A   = "0x01DB41",																A coefficient of curve
    B   = "0x01",																	B coefficient of curve
    N   = "0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED",		order of base point
    G_X = "0x0000000000000000000000000000000000000000000000000000000000000009",		base point X
    G_Y = "0x20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9",		base point Y
    H   = "0x08"																	cofactor
*/

static unsigned char curve25519_p[] = {
	0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed
};
static unsigned char curve25519_a[] = {
	0x01, 0xdb, 0x41
};
static unsigned char curve25519_b[] = {
	0x01
};
static unsigned char curve25519_g[] = {
	0x04,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
    0x20, 0xae, 0x19, 0xa1, 0xb8, 0xa0, 0x86, 0xb4, 0xe0, 0x1e, 0xdd, 0x2c, 0x77, 0x48, 0xd1, 0x4c,
   	0x92, 0x3d, 0x4d, 0x7e, 0x6d, 0x7c, 0x61, 0xb2, 0x29, 0xe9, 0xc5, 0xa2, 0x7e, 0xce, 0xd3, 0xd9
};
static unsigned char curve25519_n[] = {
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
	unsigned char * value;
	int len;
};

struct curve25519_param_entry curve25519_param[] = {
	{ 'p', curve25519_p, sizeof(curve25519_p) },
	{ 'a', curve25519_a, sizeof(curve25519_a) },
	{ 'b', curve25519_b, sizeof(curve25519_b) },
	{ 'g', curve25519_g, sizeof(curve25519_g) },
	{ 'n', curve25519_n, sizeof(curve25519_n) }
};

extern char * user_login;

/*  Forward function declaration for all static functions. Included here so we can arrange in groups regardless of
 *  which functions call others.  */

//  Utility funcs
static void		hex2str(const unsigned char * hex, int hex_len, char * str);
static int		str2hex(const char * str, unsigned char * hex);
static int		put_bignum(struct sshbuf * buf, const BIGNUM * bignum);
static void		put_num_sexpr(struct sshbuf * buf, const unsigned char * bstr, int bstr_len);
static void		populate_ssh_dir(const char * const login, char * ssh_dir);
static const char * get_user_ssh_dir(const char * const login);
static int		retrieve_ssh_key(const char * const ssh_dir, struct sshkey ** key, char ** comment);
static char *	check_seckey_dir(const char * ssh_dir);
static int		check_write_allowed(const char * out_name);
static int		hashcrypt(SHA_CTX * sha_ctx, EVP_CIPHER_CTX * aes_ctx, const unsigned char * input, int size,
	   					  unsigned char * output);

//  GPG utility funcs
static void		clamp_and_reverse_seckey(unsigned char * sk);
static void		compute_gpg_sha1_hash_sshbuf(const struct sshbuf * buf, unsigned char * hash);
static void		compute_gpg_sha1_hash_chars(const unsigned char * bstr, int bstr_len, unsigned char * hash);
static void		compute_gpg_s2k_key(const char * passphrase, int key_len, const unsigned char * salt,
									int bytes_to_hash, unsigned char * key);
static char *	generate_gpg_passphrase_from_rsa(const struct sshkey * ssh_key);
static void		compute_gpg_key_fingerprint(const gpg_message * pubkey_pkt, unsigned char * key_fp);
static BIGNUM * compute_rsa_signature(const unsigned char * digest, size_t digest_len, const struct sshkey * key);
static void		generate_gpg_kek(const unsigned char * fp, const unsigned char * shared_point, unsigned char * kek);
static struct sshbuf * encrypt_gpg_sec_parms(const struct sshbuf * buf, const unsigned char * passphrase,
	   										 unsigned char * salt, unsigned char * iv, size_t iv_len);
static int		encrypt_gpg_key_frame(const unsigned char * sym_key_frame, int frame_len, const unsigned char * key,
									  unsigned char * enc_frame);
static int		decrypt_gpg_key_frame(const unsigned char * enc_frame, int frame_len, const unsigned char * key,
									  unsigned char * frame);

//  GPG funcs to build / extract pieces of packets
static int		put_gpg_message(FILE * outfile, const gpg_message * msg);
static int		get_size_new_format(FILE *infile, ssize_t * size);
static int		get_size_old_format(FILE * infile, unsigned char len_type, ssize_t * size);
static int		get_tag_and_size(FILE * infile, gpg_tag * tag, ssize_t * size);
static int		extract_size_new_format(unsigned char * buf, ssize_t * size);
static int		extract_size_old_format(unsigned char * buf, unsigned char len_type, ssize_t * size);
static int		extract_tag_and_size(unsigned char * buf, gpg_tag * tag, ssize_t * size);
static int		generate_tag_and_size(gpg_tag tag, ssize_t size, unsigned char * buf);
static void		generate_gpg_protected_at(char * str);
static struct sshbuf * generate_gpg_rsa_pub_parms(const struct sshkey * ssh_key);
static struct sshbuf * generate_gpg_rsa_sec_parms(const struct sshkey * ssh_key);
static struct sshbuf * generate_gpg_rsa_seckey(const struct sshkey * ssh_key, const unsigned char * passphrase);
static void		generate_gpg_curve25519_keygrip(const unsigned char * q, int q_len, unsigned char * grip);
static struct sshbuf * generate_gpg_curve25519_pub_parms(const unsigned char * q, int q_len);
static struct sshbuf * generate_gpg_curve25519_sec_parms(const unsigned char * d, int d_len);
static struct sshbuf * generate_gpg_curve25519_seckey(const unsigned char * q, int q_len, const unsigned char * d,
		   											  int d_len, const unsigned char * passphrase);
static int		generate_gpg_sym_key_frame(unsigned char * sym_key_frame);
static void		generate_curve25519_ephem_shared_secret(const unsigned char * recip_pk, unsigned char * ephem_pk,
														unsigned char *secret);
static void		generate_curve25519_shared_secret(const unsigned char * sec_key, const unsigned char * pub_key,
												  unsigned char * secret);
static int		encrypt_input_file(FILE * infile, FILE * outfile, SHA_CTX * sha_ctx, EVP_CIPHER_CTX * aes_ctx);

static int		extract_curve25519_seckey(const unsigned char * enc_data, int len, const struct sshkey * ssh_key,
	   					  				  const unsigned char * salt, int hash_bytes, const unsigned char * iv,
										  unsigned char * d);
static int		get_gpg_curve25519_seckey(const unsigned char * buf, int buf_len, const struct sshkey * ssh_key,
	   									  unsigned char * d);
static int		extract_ephemeral_key(const unsigned char * msg, const unsigned char ** ephem_pk);
static int		extract_sym_key(const unsigned char * msg, const unsigned char * secret, const unsigned char * fp,
								unsigned char * sym_key);
static int		process_enc_data_hdr(SHA_CTX * sha_ctx, EVP_CIPHER_CTX * aes_ctx, FILE * infile,
									 unsigned char * output, char * fname, int * num_dec, ssize_t * len, int * extra);
static int		process_enc_data(SHA_CTX * sha_ctx, EVP_CIPHER_CTX * aes_ctx, FILE * infile, FILE * outfile,
								 unsigned char * output, int offset, ssize_t len, int extra);

//  GPG packet generation funcs
static void		generate_gpg_public_key_packet(const struct sshkey * ssh_key, gpg_message * msg);
static void		generate_gpg_curve25519_subkey_packet(const unsigned char * pub_key, size_t pk_len, gpg_message * msg);
static void		generate_gpg_user_id_packet(const char * user_id, gpg_message * msg);
static void		generate_gpg_pk_uid_signature_packet(const gpg_message * pubkey_pkt, const gpg_message * uid_pkt,
						                             const struct sshkey * key, int sig_class,
													 const unsigned char * key_id, gpg_message * msg);
static void		generate_gpg_trust_packet(gpg_message * msg);
static int		generate_gpg_pkesk_packet(const gpg_public_key * key, unsigned char * sym_key_frame, int frame_len, 
										  gpg_message * msg);
static int		generate_gpg_literal_data_packet(const char * fname, size_t file_len, time_t mod_time,
												 unsigned char * data_pkt_hdr);
static int		write_gpg_mdc_packet(FILE * outfile, SHA_CTX * sha_ctx, EVP_CIPHER_CTX * aes_ctx);

//  GPG packet retrieval funcs
static gpg_message * get_pub_key_packet(FILE * infile);
static gpg_message * get_curve25519_key_packet(FILE * infile);
static int		get_gpg_pkesk_packet(FILE * infile, const char * key_id, unsigned char * msg, gpg_tag * next_tag,
	   								 int * next_len);

//  GPG file manipulation funcs
static FILE *	open_rsa_seckey_file(const char * seckey_dir, const struct sshkey * ssh_key);
static FILE *	open_curve25519_seckey_file(const char * seckey_dir, const char * mode, const unsigned char * q,
	   										int q_len);
static FILE *	open_encrypted_output_file(const char * fname, char * enc_fname);
static FILE *	open_decrypted_output_file(const char * fname, const char * local_path, char * dec_fname);

static int		write_public_key_file(FILE * pub_file, const struct sshkey * ssh_key, const unsigned char * pub_subkey,
							          const char * uid, unsigned char * key_fp, unsigned char * subkey_fp);
static int		write_secret_key_files(const char * ssh_dir, const struct sshkey * ssh_key, const unsigned char * q,
	  								   int q_len, const unsigned char * d, int d_len, const char * passphrase);
static int		write_key_to_pubkey(FILE * outfile, const char * key_name, const unsigned char * pub_key, int len,
									const unsigned char * fp, const char * uid);
static int		write_pubkey_file(const char * login, struct sshkey * ssh_key, const unsigned char * pub_key,
								  const char * uid, const unsigned char * key_fp, const unsigned char * subkey_fp);
static int		generate_iron_keys(const char * const ssh_dir, const char * const login);
static int		write_encrypted_data_file(FILE * infile, const char * fname, FILE * outfile, unsigned char * sym_key);

static int		get_encryption_key(const char * login, unsigned char * pub_key, size_t * pub_key_len,
								   unsigned char * sec_key, size_t * sec_key_len, unsigned char * fp,
								   unsigned char * signer_fp);
static int		read_pubkey_file(const char * login, unsigned char * rsa_key, size_t * rsa_key_len,
							   	 unsigned char * cv25519_key, size_t * cv25519_key_len, unsigned char * rsa_fp,
								 unsigned char * cv25519_fp, char * uid);


//  GPG trustdb file funcs
static int		write_trustdb_htbl(FILE * tdb_file, const unsigned char * key, int key_len);
static void		generate_gpg_trustdb_version(unsigned char * rec);
static void		generate_gpg_trustdb_trust(unsigned char * rec, const unsigned char * key, int key_len, int next_rec);
static void		generate_gpg_trustdb_valid(unsigned char * rec, const char * uid);
static int		write_trustdb_file(const char * ssh_dir, const unsigned char * key, size_t key_len, const char * uid);

//  Recipient list funcs
static int		get_recipients(const gpg_public_key ** recip_list);

//================================================================================
//  Utility funcs
//================================================================================
/**
 *  Convert bytes to hex string.
 *
 *  Convert a byte array into its corresponding representation as ASCII hex characters.
 *
 *  @param hex Byte string
 *  @param hex_len Num bytes in hex
 *  @param str Place to put ASCII string. Must be at least 2 * hex_len + 1 bytes
 */
static void
hex2str(const unsigned char * hex, int hex_len, char * str)
{
	char * ptr = str;
	const unsigned char * hptr = hex;

	const char hex_digit[] = {
	   	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
	};

	for (int ct = 0; ct < hex_len; ct++, hptr++) {
		*ptr++ = hex_digit[*hptr >> 4];
		*ptr++ = hex_digit[*hptr & 0x0f];
	}

	*ptr = '\0';
}

/**
 *  Convert hex string to bytes.
 *
 *  Convert a string of ASCII hex chars into a byte array. String should have an even number of chars.
 *
 *  @param str String of ASCII hex
 *  @param hex Place to write byte array. Should point to strlen(str) / 2 bytes
 *  @return int Num bytes in hex, negative number if error
 */
static int
str2hex(const char * str, unsigned char * hex)
{
	int retval = -1;
	const char * ptr = str;
	unsigned char * hptr = hex;
	*hptr = '\0';

	if ((strlen(str) % 2) == 0) {
		while (*ptr) {
			unsigned int t;
			if (sscanf(ptr, "%2x", &t) != 1) {
				break;
			}
			ptr += 2;
			*(hptr++) = t;
		}
		retval = hptr - hex;
	}
	return retval;
}

/**
 *  Write bignum to buffer.
 *
 *  Write an OpenSSL BIGNUM in the MPI format used in GPG into an sshbuf. (two bytes containing the length
 *  in bits, MSB-first, followed by the bits, MSB first, padded with leading zero bits to full octets).
 *
 *  @param buf Place to write MPI
 *  @param bignum Value to convert to MPI format
 *  @return int 0 if successful, negative number if error
 */
static int
put_bignum(struct sshbuf * buf, const BIGNUM * bignum)
{
	int retval = -1;
	int num_bits = BN_num_bits(bignum);
	int num_bytes = BN_num_bytes(bignum);

	if (sshbuf_put_u16(buf, num_bits) == 0) {
		unsigned char tmp[1032];
		BN_bn2bin(bignum, tmp);
		if (sshbuf_put(buf, tmp, num_bytes) == 0) {
			retval = 0;
		}
	}

	return retval;
}

/**
 *  Write byte array to buffer as S-expression.
 *
 *  Format an array of bytes as a GPG S-expression (length in bytes, as an ASCII string, followed by ':', then
 *  the byte array).
 *
 *	The first byte of the S-expression needs to not have the high (sign) bit set. If it does, add a 0 byte at
 *	the start.
 *
 *  @param buf Place to write S-expression
 *  @param bstr Byte array
 *  @param bstr_len Num bytes in bstr
 */
static void
put_num_sexpr(struct sshbuf * buf, const unsigned char * bstr, int bstr_len)
{
	if (*bstr > 0x7f) {
		bstr_len++;
	}

	char tmp[32];
	int tlen = sprintf(tmp, "%d:", bstr_len);
	sshbuf_put(buf, tmp, tlen);

	if (*bstr > 0x7f) {
		sshbuf_put_u8(buf, 0);
		sshbuf_put(buf, bstr, bstr_len - 1);
	} else {
		sshbuf_put(buf, bstr, bstr_len);
	}
}

/**
 *  Given a login, generate path of ~<login>/.ssh/.
 *
 *  Find the home directory for the specified login and append '/.ssh/ to it.
 *
 *  @param login User for whom to generate path
 *  @param ssh_dir Place to write path (at least PATH_MAX + 1 chars)
 */
static void
populate_ssh_dir(const char * const login, char * ssh_dir)
{
	struct passwd * pw = getpwnam(login);
	if (pw != NULL) {
		snprintf(ssh_dir, PATH_MAX, "%s/.ssh/", pw->pw_dir);
		ssh_dir[PATH_MAX] = '\0';
	} else {
		*ssh_dir = '\0';
	}
}

/**
 *  Generate the path to the .ssh directory for the specified login.
 *
 *  Cache the sshdir if the login is the current user. Return cached dir if login user_login.
 *  If path can't be determined, returns an empty string.
 *
 *  Nope, this is not even close to thread safe. Not a problem for now.
 *
 *  @param login Login of user for whom to get path to .ssh dir.
 *  @return char * Path, or empty string if unable to determine
 */
static const char *
get_user_ssh_dir(const char * const login)
{
	/* If the requested login is the current user's login, cache the ssh directory value, since we will
	 * probably need it a few times.
	 */
	static char curr_ssh_dir[PATH_MAX + 1] = { 0 };

	if (strcmp(login, user_login) == 0) {
		if (!(*curr_ssh_dir)) {
			populate_ssh_dir(login, curr_ssh_dir);
		}
		return curr_ssh_dir;
	}
	else {
		static char ssh_dir[PATH_MAX + 1];
		populate_ssh_dir(login, ssh_dir);
		return ssh_dir;
	}
}

/**
 *  Read key from user's SSH key files.
 *
 *  Fetch the key data from the user's private SSH key file. If successfully, opens the corresponding public key
 *  file to get the comment.
 *
 *  *** Currently only handles RSA files.
 *
 *  @param ssh_dir Path to user's ssh directory
 *  @param key output key read from file
 *  @param comment output comment read from public key file. Should point to at least COMMENT_MAX + 1 chars
 */
static int
retrieve_ssh_key(const char * const ssh_dir, struct sshkey ** key, char ** comment)
{
	int retval = -1;
	static char cached_ssh_dir[PATH_MAX + 1] = "";
	static struct sshkey cached_key;
	static char cached_comment[COMMENT_MAX + 1];

	if (strcmp(ssh_dir, cached_ssh_dir) == 0) {
		*comment = strdup(cached_comment);
		*key = malloc(sizeof(cached_key));
		memcpy(*key, &cached_key, sizeof(cached_key));
		retval = 0;
	} else {
#ifdef WITH_OPENSSL
		OpenSSL_add_all_algorithms();
#endif

		char ssh_key_file[PATH_MAX + 1];
		snprintf(ssh_key_file, PATH_MAX, "%sid_rsa", ssh_dir);
		ssh_key_file[PATH_MAX] = '\0';

		retval = sshkey_load_private(ssh_key_file, "", key, comment);
		if (retval == SSH_ERR_KEY_WRONG_PASSPHRASE) {
			char * passphrase = read_passphrase("Enter passphrase for SSH key file: ", 0);
			retval = sshkey_load_private(ssh_key_file, passphrase, key, comment);
			explicit_bzero(passphrase, strlen(passphrase));
			free(passphrase);
		}

		//  If we succeeded in reading the private key, read the public key to get the comment field,
		//  which will typically be the user's identification (i.e. email address)
		if (retval == 0) {
			struct sshkey * tmp_key;

			strncat(ssh_key_file, ".pub", PATH_MAX);
			retval = sshkey_load_public(ssh_key_file, &tmp_key, comment);
			if (retval == 0) {
				strncpy(cached_ssh_dir, ssh_dir, PATH_MAX);
				cached_ssh_dir[PATH_MAX] = '\0';
				memcpy(&cached_key, *key, sizeof(struct sshkey));
				strncpy(cached_comment, *comment, COMMENT_MAX);
				cached_comment[COMMENT_MAX] = '\0';
			}
		}
	}
	return retval;
}

/**
 *  Check whether the ssh directory contains a private key subdir.
 *
 *  Looks in the specified path for a private-keys-v1.d subdirectory.
 *
 *  @param ssh_dir Path to the user's .ssh directory (usually under ~<login>
 *  @return char * Path of private key subdir (at least PATH_MAX + 1 chars). Caller should free
 */
static char *
check_seckey_dir(const char * ssh_dir)
{
	char dir_name[PATH_MAX + 1];
	char * name_ptr = NULL;

	int len = snprintf(dir_name, PATH_MAX, "%s%s/", ssh_dir, GPG_SECKEY_SUBDIR);
	dir_name[PATH_MAX] = '\0';
	if (len < (int) sizeof(dir_name)) {
		if (mkdir(dir_name, 0700) == 0 || errno == EEXIST) {
			name_ptr = xstrdup(dir_name);
		}
	}

	return name_ptr;
}

/**
 *  Determine if file can be written.
 *
 *  If file doesnt exist, assume OK. If it does exist, prompt user to see if it is OK to overwrite.
 *
 *  @param out_name Path to file to check
 *  @return int 1 if OK, 0 if not
 */
static int
check_write_allowed(const char * out_name)
{
	int retval = 1;
	//  Check to see if the file already exists. If so, ask the user whether to overwrite
	if (access(out_name, F_OK) == 0) {
		printf("Output file %s already exists - overwrite? (y/N)? ", out_name);
		char line[80];
		line[0] = '\0';
		fgets(line, sizeof(line), stdin);
		if (line[0] != 'y' && line[0] != 'Y') {
			retval = 0;
		}
	}
	return retval;
}

/**
 *  Simultaneously update a SHA1 hash and an AES encryption with data buffer.
 *
 *  Given a block of data, add to running SHA1 hash, and AES encrypt the data and write to output buffer.
 *
 *  @param sha_ctx Running SHA1 hash
 *  @param aes_ctx Running AES encryption of data
 *  @param input Buffer to hash/encrypt
 *  @param size Num bytes in input
 *  @param output Place to write encrypted output generated by AES
 *  @return int Num bytes written to output
 */
static int
hashcrypt(SHA_CTX * sha_ctx, EVP_CIPHER_CTX * aes_ctx, const unsigned char * input, int size, unsigned char * output)
{
	int num_written = -1;
	SHA1_Update(sha_ctx, input, size);
	EVP_EncryptUpdate(aes_ctx, output, &num_written, input, size);
	return num_written;
}


//================================================================================
//  GPG utility funcs
//================================================================================


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
static void
clamp_and_reverse_seckey(unsigned char * sk)
{
	//  "Clamping" - Zero lowest three bits and highest bit of secret key, set next-to-highest bit. But
	//  libsodium/nacl represents the components little-endian (least signficant byte first).
	sk[crypto_box_SECRETKEYBYTES - 1] &= 0x7f;
	sk[crypto_box_SECRETKEYBYTES - 1] |= 0x40;
	sk[0] &= 0xf8;

	//  Reverse the whole key in place.
	for (unsigned int ct = 0; ct < crypto_box_SECRETKEYBYTES / 2; ct++) {
		unsigned int ct2 = crypto_box_SECRETKEYBYTES - 1 - ct;
		unsigned char tmp = sk[ct];
		sk[ct]  = sk[ct2];
		sk[ct2] = tmp;
	}
}

/**
 *  Calculate SHA1 hash of sshbuf contents.
 *
 *  @param buf Buffer to hash
 *  @param hash Place to write computed hash - at least SHA_DIGEST_LENGTH bytes
 */
static void
compute_gpg_sha1_hash_sshbuf(const struct sshbuf * buf, unsigned char * hash)
{
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, sshbuf_ptr(buf), sshbuf_len(buf));
	SHA1_Final(hash, &ctx);
}

/**
 *  Calculate SHA1 hash of byte array.
 *
 *  @param bstr Byte array
 *  @param bstr_len Num bytes in bstr
 *  @param hash Place to write computed hash - at least SHA_DIGEST_LENGTH bytes
 */
static void
compute_gpg_sha1_hash_chars(const unsigned char * bstr, int bstr_len, unsigned char * hash)
{
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, bstr, bstr_len);
	SHA1_Final(hash, &ctx);
}

/**
 *  Compute String-to-Key (s2k) key from passphrase.
 *
 *  Uses the GPG algorithm to convert a passphrase into a key that can be used for symmetric key encryption.
 *  Why use a standard PBKDF?
 *
 *  Expects a nulll-terminated string as the passphrase and the specifier of the length of key it should
 *  generate. Outputs 8 bytes of random salt, and the requested number of bytes of key.
 *
 *  If we are going to encrypt with AES256, we need 32 bytes of key. To generate, we start with 8 bytes
 *  of random salt, followed by the passphrase. This string will be hashed repeatedly to generate the key.
 *  We are using SHA256 for the hash, which outputs 32 bytes, so we need only one hash. If a key of more 
 *  than 32 bytes is needed, we need to set up multiple hash contexts, so that the output of each of them
 *  concatenated together is the requested number of bytes. So, for example, if a 33 to 64 byte key is needed,
 *  we would create two hash contexts. If a 65 to 96 byte key is needed, we would create three hash contexts,
 *  etc.
 *
 *  To generate different data from each hash, each successive hash is initialized with one more byte of zeroes.
 *  The first hash has no initializer, the second has one byte of zeros, the third has two bytes, etc.
 *
 *  We first generate eight bytes of random salt and use that as a prefix for the passphrase. This new string
 *  is hashed repeatedly by each hash, until we have hashed >= S2K_ITER_BYTE_COUNT bytes. The key is formed by
 *  concatenating the output of the hashes, discarding the rightmost bytes of the last hash when we have enough
 *  bytes for the key.
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
compute_gpg_s2k_key(const char * passphrase, int key_len, const unsigned char * salt, int bytes_to_hash,
		unsigned char * key)
{
	int len = strlen(passphrase) + S2K_SALT_BYTES;
	unsigned char * salted_passphrase = malloc(len);

	memcpy(salted_passphrase, salt, S2K_SALT_BYTES);
	memcpy(salted_passphrase + S2K_SALT_BYTES, passphrase, len - S2K_SALT_BYTES);

	static unsigned char zero_buf[1] = {'\0'};

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
	unsigned char * key_ptr = key;
	for (ct = 0, num_bytes_left = key_len; num_bytes_left > 0; num_bytes_left -= SHA_DIGEST_LENGTH, ct++) {
		unsigned char digest[SHA_DIGEST_LENGTH];
		SHA1_Final(digest, &(hash[ct]));
		memcpy(key_ptr, digest, (num_bytes_left < SHA_DIGEST_LENGTH) ? num_bytes_left : SHA_DIGEST_LENGTH);
		key_ptr += num_bytes_left;
	}

	assert (ct == num_hashes);
	free(hash);
}

/**
 *  Create a passphrase from an SSH RSA key
 *
 *  Generate a text passphrase to secure the GPG secret RSA key created from an SSH RSA key.
 *  Hash the RSA secret key 256 times (using SHA256), then uuencode the hash.
 *
 *  In order to retrieve the RSA secret key, the user needs the passphrase for the SSH key, so this
 *  should provide a reasonable level of security.
 *
 *  @param ssh_key Struct containing the RSA key
 */
static char *
generate_gpg_passphrase_from_rsa(const struct sshkey * ssh_key)
{
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	unsigned char tmp[1024];
	int len = BN_bn2bin(ssh_key->rsa->d, tmp);
	for (int ct = 0; ct < 256; ct++) {
		SHA256_Update(&ctx, tmp, len);
	}

	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256_Final(digest, &ctx);

	char str[SHA256_DIGEST_LENGTH * 4 / 3 + 3];
	uuencode(digest, sizeof(digest), str, sizeof(str));

	return strdup(str);
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
static void
compute_gpg_key_fingerprint(const gpg_message * pubkey_pkt, unsigned char * key_fp)
{
	SHA_CTX  ctx;
	unsigned char hdr[3];

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
 *  Sign a hash using an RSA key.
 *
 *  Computes the RSA signature of a hash given the RSA signing key (needs to have secret key populated).
 *
 *  @param digest Byte array containing hash
 *  @param digest_len Num bytes in digest
 *  @param key RSA key to use to sign hash
 *  @return BIGNUM * bignum containing the computed signature, NULL if error
 */
static BIGNUM *
compute_rsa_signature(const unsigned char * digest, size_t digest_len, const struct sshkey * key)
{

	size_t rsa_len = RSA_size(key->rsa);
	unsigned int len;
	unsigned char * tmp_sig = malloc(rsa_len);

	if (RSA_sign(NID_sha256, digest, digest_len, tmp_sig, &len, key->rsa) != 1) {
		return NULL;
	} else {
		BIGNUM * sig = BN_new();
		BN_bin2bn(tmp_sig, len, sig);
		free(tmp_sig);
		return sig;
	}

}

/**
 *  Generate a Key Encryption Key.
 *
 *  When a symmetric key is used for a PGP message, it needs to be encrypted to a specific user. This requires
 *  the generation of a Key Encryption Key (KEK). This requires the fingerprint of the recipient's key and a
 *  shared point computed using Elliptic Curve Diffie Hellman (ECDH). The KEK is a SHA256 hash of these parameters
 *  plus some related info. We are using AES128 for the key encryption, so we just use use the first bytes of
 *  the has as the KEK.
 *
 *  @param fp Fingerprint of recipient's main (signing) key
 *  @param shared_point Output of ECDH algorithm given ephemeral secret key and recipient's public key
 *  @param kek Place to put generated kek. Should point to at least AES128_KEY_BYTES bytes
 */
static void
generate_gpg_kek(const unsigned char * fp, const unsigned char * shared_point, unsigned char * kek)
{
#define SENDER_STRING "Anonymous Sender    "

	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	unsigned char buf[] = { 0x00, 0x00, 0x00, 0x01  };

	SHA256_Update(&ctx, buf, sizeof(buf));

	SHA256_Update(&ctx, shared_point, crypto_box_BEFORENMBYTES);
	SHA256_Update(&ctx, curve25519_oid, sizeof(curve25519_oid));
	buf[0] = GPG_PKALGO_ECDH;
	SHA256_Update(&ctx, buf, 1);
	SHA256_Update(&ctx, curve25519_kek_parm, sizeof(curve25519_kek_parm));
	SHA256_Update(&ctx, SENDER_STRING, strlen(SENDER_STRING));
	SHA256_Update(&ctx, fp, GPG_KEY_FP_LEN);

	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256_Final(digest, &ctx);
	memcpy(kek, digest, AES128_KEY_BYTES);
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
 *  @param iv Place to write initializatoin vector. At least GPG_SECKEY_IV_BYTES
 *  @param iv_len Num bytes to write into IV
 *  @return sshbuf * Buffer containing encrypted S-expression. Caller should sshbuf_free
 */
static struct sshbuf *
encrypt_gpg_sec_parms(const struct sshbuf * buf, const unsigned char * passphrase, unsigned char * salt,
		unsigned char * iv, size_t iv_len)
{
	struct sshbuf * obuf = NULL;

	unsigned char key[AES128_KEY_BYTES];

	randombytes_buf(salt, S2K_SALT_BYTES);
	compute_gpg_s2k_key(passphrase, sizeof(key), salt, S2K_ITER_BYTE_COUNT, key);
	randombytes_buf(iv, iv_len);

	struct sshcipher_ctx ciphercontext;
	const struct sshcipher * cipher = cipher_by_name("aes128-cbc");

	memset(&ciphercontext, 0, sizeof(ciphercontext));
	int retval = cipher_init(&ciphercontext, cipher, key, sizeof(key), iv, iv_len, CIPHER_ENCRYPT);

	if (retval == 0) {
		unsigned char * input = malloc(sshbuf_len(buf) + AES128_KEY_BYTES);
		memcpy(input, sshbuf_ptr(buf), sshbuf_len(buf));
		randombytes_buf(input + sshbuf_len(buf), AES128_KEY_BYTES);
		int enc_len = AES128_KEY_BYTES * ((sshbuf_len(buf) + AES128_KEY_BYTES) / AES128_KEY_BYTES);
		unsigned char * output;
		obuf = sshbuf_new();
		sshbuf_reserve(obuf, enc_len, &output);
		retval = cipher_crypt(&ciphercontext, 0, output, input, enc_len, 0, 0);
		if (retval != 0) {
			sshbuf_free(obuf);
			obuf = NULL;
		}
	}

	return obuf;
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
 *  @param key Generated Key Encryption Key
 *  @param enc_frame Place to write encrypted frame. Should point to at least AES256_KEY_BYTES + 2 * AES_WRAP_BLOCK_SIZE bytes
 *  @return int Num bytes in enc_frame, or negative number if error
 */
static int
encrypt_gpg_key_frame(const unsigned char * sym_key_frame, int frame_len, const unsigned char * key,
					  unsigned char * enc_frame)
{
	EVP_CIPHER_CTX ciphctx;
	const EVP_CIPHER * cipher = EVP_aes_128_wrap();

	int written = -1;

	EVP_CIPHER_CTX_init(&ciphctx);
	EVP_CIPHER_CTX_set_flags(&ciphctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
	if (EVP_EncryptInit_ex(&ciphctx, cipher, NULL /* dflt engine */, key, NULL /* dflt iv */)) {
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
decrypt_gpg_key_frame(const unsigned char * enc_frame, int frame_len, const unsigned char * key,
					  unsigned char * frame)
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


//================================================================================
//  GPG funcs to build / extract pieces of packets
//================================================================================

/**
 *  Write packet to file.
 *
 *  @param outfile File to which to write
 *  @param msg Packet to write
 *  @return int 0 if successful, negative number if error
 */
static int
put_gpg_message(FILE * outfile, const gpg_message * msg)
{
	int retval = -1;
	char buf[7];

	int buf_len = generate_tag_and_size(msg->tag, msg->len, buf);
	if (buf_len > 0 && fwrite(buf, sizeof(char), buf_len, outfile) == (size_t) buf_len) {
		const unsigned char * tmp_ptr = sshbuf_ptr(msg->data);
		int num_written = fwrite(tmp_ptr, sizeof(unsigned char), msg->len, outfile);
		if (num_written == msg->len) {
			retval = 0;
		}
	}

	return retval;
}

/**
 *  Read the size bytes following GPG tag in new format from file.
 *
 *  If a byte is a new-format GPG tag byte, extract the following length. The format of the length is a mess -
 *  if it is less than 0xc0, the length is one byte. If it is between 0xc0 and 0xxxxx, it is two bytes. If it
 *  is longer, it is five bytes. There is also a special one-byte partial length that is a power of 2.
 *
 *  Doesn't support the indeterminate length yet.
 *
 *  @param infile File to read
 *  @param size Size read from file
 *  @return int 0 if successful, negative number if error
 */
static int
get_size_new_format(FILE *infile, ssize_t * size)
{
	int retval = -1;
	unsigned char buf[4];

	size_t num_read = fread(buf, 1, 1, infile);
	if (num_read > 0) {
		unsigned char len_octet = buf[0];
		if (len_octet < 192) {
			*size = len_octet;
			retval = 0;
		} else if (len_octet < 224) {
			num_read = fread(buf, 1, 1, infile);
			if (num_read > 0) {
				*size = ((len_octet - 192) << 8) + buf[0] + 192;
				retval = 0;
			}
		} else if (len_octet == 0xff) {
			num_read = fread(buf, 1, 4, infile);
			if (num_read == 4) {
				*size = 0;
				for (int i = 0; i < 4; i++) {
					*size = (*size << 8) + buf[i];
				}
				retval = 0;
			}
		} else {
			// Partial body length
			*size = 1 << (len_octet - 224);
			retval = 0;
		}
	}

	return retval;
}

/**
 *  Read the size bytes following GPG tag in old format from file.
 *
 *  If a byte is an old-format GPG tag byte, extract the following length. The length of the size is encoded
 *  in the "length type" (last two bits of the tag byte).
 *
 *  @param infile File to read
 *  @param len_type Indicator of how long size is
 *  @param size Size read from file
 *  @return int 0 if successful, negative number if error
 */
static int
get_size_old_format(FILE * infile, unsigned char len_type, ssize_t * size)
{
	int retval = -1;
	unsigned char buf[4];
	int num_octets;

	switch (len_type) {
		case 0: num_octets = 1; break;
		case 1: num_octets = 2; break;
		case 2: num_octets = 4; break;
		case 3: num_octets = -1; break;
	}

	if (num_octets > 0) {
		int num_read = fread(buf, sizeof(unsigned char), num_octets, infile);
		if (num_read == num_octets) {
			*size = 0;
			for (int i = 0; i < num_octets; i++) {
				*size = (*size << 8) + buf[i];
			}
			retval = 0;
		}
	} else {
		*size = -1;
		retval = 0;
	}

	return retval;
}

/**
 *  Read the GPG tag and following size from a file.
 *
 *  @param infile File to read
 *  @param tag Place to write recovered tag
 *  @param size Place to write recovered size
 *  @return int 0 if successful, negative number if error
 */
static int
get_tag_and_size(FILE * infile, gpg_tag * tag, ssize_t * size)
{
	int retval = -1;

	if (tag != NULL && size != NULL) {
		unsigned char buf[4];

		int num_read = fread(buf, 1, 1, infile);

		if (num_read == 1) {
			unsigned char tag_byte = buf[0];

			if ((tag_byte & 0x80) == 0x80) {
				int new_format = tag_byte & 0x40;

				if (new_format) {
					*tag = (gpg_tag) (tag_byte & 0x3f);
					retval = get_size_new_format(infile, size);

				} else {
					*tag = (gpg_tag) ((tag_byte & 0x3c) >> 2);
					retval = get_size_old_format(infile, (tag_byte & 0x03), size);
				}
			}
		}
	}

	return retval;
}

/**
 *  Extract the size bytes following GPG tag in new format from byte array.
 *
 *  If a byte is a new-format GPG tag byte, extract the following length. The format of the length is a mess -
 *  if it is less than 0xc0, the length is one byte. If it is between 0xc0 and 0xxxxx, it is two bytes. If it
 *  is longer, it is five bytes. There is also a special one-byte partial length that is a power of 2.
 *
 *  Doesn't support the indeterminate length yet.
 *
 *  @param buf Byte array to read
 *  @param size Size read from array
 *  @return int Num bytes consumed from array, negative number if error
 */
static int
extract_size_new_format(unsigned char * buf, ssize_t * size)
{
	int retval = -1;
	unsigned char len_octet = buf[0];
	if (len_octet < 192) {
		*size = len_octet;
		retval = 1;
	} else if (len_octet < 224) {
		*size = ((len_octet - 192) << 8) + buf[1] + 192;
		retval = 2;
	} else if (len_octet == 0xff) {
		*size = 0;
		for (int i = 1; i < 5; i++) {
			*size = (*size << 8) + buf[i];
		}
		retval = 5;
	} else {
		// Partial body length
		*size = 1 << (len_octet - 224);
		retval = 1;
	}

	return retval;
}

/**
 *  Read the size bytes following GPG tag in old format from byte array.
 *
 *  If a byte is an old-format GPG tag byte, extract the following length. The length of the size is encoded
 *  in the "length type" (last two bits of the tag byte).
 *
 *  @param buf Byte array to read
 *  @param len_type Indicator of how long size is
 *  @param size Size read from file
 *  @return int Num bytes consumed from buf, negative number if error
 */
static int
extract_size_old_format(unsigned char * buf, unsigned char len_type, ssize_t * size)
{
	int retval = -1;
	int num_octets;

	switch (len_type) {
		case 0: num_octets = 1; break;
		case 1: num_octets = 2; break;
		case 2: num_octets = 4; break;
		case 3: num_octets = -1; break;
	}

	if (num_octets > 0) {
		*size = 0;
		for (int i = 0; i < num_octets; i++) {
			*size = (*size << 8) + buf[i];
		}
		retval = num_octets;
	} else {
		*size = -1;
		retval = 0;
	}

	return retval;
}

/**
 *  Read the GPG tag and following size from byte array.
 *
 *  @param buf Byte array to read
 *  @param tag Place to write recovered tag
 *  @param size Place to write recovered size
 *  @return int Num bytes consumed from buf, negative number if error
 */
static int
extract_tag_and_size(unsigned char * buf, gpg_tag * tag, ssize_t * size)
{
	int retval = -2;

	if (tag != NULL && size != NULL) {
		unsigned char tag_byte = buf[0];

		if ((tag_byte & 0x80) == 0x80) {
			int new_format = tag_byte & 0x40;

			if (new_format) {
				*tag = (gpg_tag) (tag_byte & 0x3f);
				retval = extract_size_new_format(buf + 1, size);

			} else {
				*tag = (gpg_tag) ((tag_byte & 0x3c) >> 2);
				retval = extract_size_old_format(buf + 1, (tag_byte & 0x03), size);
			}
		}
	}

	return retval + 1;
}

/**
 *  Generate GPG tag and size header.
 *
 *  Give a tag and size, format appropriately in GPG old or new format and write to byte array.
 *
 *  @param tag Tag for packet
 *  @param size Length of packet body
 *  @param buf Place to write packet header
 *  @return int Num bytes written to buf, neagtive number if error
 */
static int
generate_tag_and_size(gpg_tag tag, ssize_t size, unsigned char * buf)
{
	int len = -1;

	if ((int) tag < 16) {
		//  Tag small enough to fit into an old-format tag octet and length.
		buf [0] = 0x80 | (tag << 2);

		if (size < 0) {
			buf [0] |= 3;
			len = 1;
		} else if (size <= 0xff) {
			buf [1] = (unsigned char) size;
			len = 2;
		} else if (size <= 0xffff) {
			buf [0] |= 1;
			buf [1] = size >> 8;
			buf [2] = size;
			len = 3;
		} else if (size <= 0xffffffff) {
			buf [0] |= 2;
			buf [1] = size >> 24;
			buf [2] = size >> 16;
			buf [3] = size >> 8;
			buf [4] = size;
			len = 5;
		}
	} else if ((int) tag < 64) {
		//  Use a new-format tag octet and length.
		buf [0] = 0xc0 | tag;

		if (size < 192) {
			buf [1] = size;
			len = 2;
		} else if (size < 0x20c0) {
			buf [1] = ((size - 192) >> 8) + 192;
			buf [2] = ((size - 192) & 0xff);
			len = 3;
		} else if (size < 0x100000000) {
			buf [1] = 0xff;
			buf [2] = size >> 24;
			buf [3] = size >> 16;
			buf [4] = size >> 8;
			buf [5] = size;
			len = 6;
		}
		//  Don't handle partial body length yet.
	}

	return len;
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
generate_gpg_rsa_pub_parms(const struct sshkey * ssh_key)
{
	struct sshbuf * pub_parms = sshbuf_new();
	unsigned char tmp[512];
	int len = BN_bn2bin(ssh_key->rsa->n, tmp);
	sshbuf_put(pub_parms, "(1:n", 4);
	put_num_sexpr(pub_parms, tmp, len);
	len = BN_bn2bin(ssh_key->rsa->e, tmp);
	sshbuf_put(pub_parms, ")(1:e", 5);
	put_num_sexpr(pub_parms, tmp, len);
	sshbuf_put_u8(pub_parms, ')');

	return pub_parms;
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
 *  @return sshbuf * Pointer to sshbuf containing S-expression. Caller should ssh_free.
 */
static struct sshbuf *
generate_gpg_rsa_sec_parms(const struct sshkey * ssh_key)
{
	struct sshbuf * sec_parms = sshbuf_new();
	unsigned char tmp[1024];
	int len = BN_bn2bin(ssh_key->rsa->d, tmp);
	sshbuf_put(sec_parms, "(1:d", 4);
	put_num_sexpr(sec_parms, tmp, len);
	len = BN_bn2bin(ssh_key->rsa->q, tmp);
	sshbuf_put(sec_parms, ")(1:p", 5);
	put_num_sexpr(sec_parms, tmp, len);
	len = BN_bn2bin(ssh_key->rsa->p, tmp);
	sshbuf_put(sec_parms, ")(1:q", 5);
	put_num_sexpr(sec_parms, tmp, len);
	len = BN_bn2bin(ssh_key->rsa->iqmp, tmp);
	sshbuf_put(sec_parms, ")(1:u", 5);
	put_num_sexpr(sec_parms, tmp, len);
	sshbuf_put_u8(sec_parms, ')');

	return sec_parms;
}

/**
 *  Generate S-expression containing RSA parameters.
 *
 *  Creates the S-expression that contains each of the parameters of the RSA key - first the public key
 *  (n and e), then a nested S-expression containing the secret key (d, p, q, u). The later is encrypted
 *  before writing into the final S-expression.
 *
 *  @param ssh_key RSA key
 *  @param passphrase ASCII string used to protect encrypted portion
 *  @return sshbuf * Buffer containing S-expression. Caller should sshbuf_free
 */
static struct sshbuf *
generate_gpg_rsa_seckey(const struct sshkey * ssh_key, const unsigned char * passphrase)
{
	/* First, we need to compute the hash of the key data. The string to be hashed is unfortunately not quite
	 * exactly the same format as the subsequent string to write to the key, so for now we won't worry about
	 * reusing pieces and parts.
	 */
	char protected_at[PROTECTED_AT_LEN];

	generate_gpg_protected_at(protected_at);

	struct sshbuf * pub_parms = generate_gpg_rsa_pub_parms(ssh_key);
	struct sshbuf * sec_parms = generate_gpg_rsa_sec_parms(ssh_key);

	struct sshbuf * hash_str = sshbuf_new();

	sshbuf_put(hash_str, "(3:rsa", 6);
	sshbuf_putb(hash_str, pub_parms);
	sshbuf_putb(hash_str, sec_parms);
	sshbuf_put(hash_str, protected_at, strlen(protected_at));
	sshbuf_put_u8(hash_str, ')');

	unsigned char hash[SHA_DIGEST_LENGTH];
	compute_gpg_sha1_hash_sshbuf(hash_str, hash);

	struct sshbuf * sec_str = sshbuf_new();
	sshbuf_put_u8(sec_str, '(');
	sshbuf_put_u8(sec_str, '(');
	sshbuf_putb(sec_str, sec_parms);
	sshbuf_put_u8(sec_str, ')');
	sshbuf_putf(sec_str, "(4:hash4:sha1%lu:", sizeof(hash));
	sshbuf_put(sec_str, hash, sizeof(hash));
	sshbuf_put_u8(sec_str, ')');
	sshbuf_put_u8(sec_str, ')');

	unsigned char salt[S2K_SALT_BYTES];
	unsigned char iv[GPG_SECKEY_IV_BYTES];
	struct sshbuf * enc_sec_parms = encrypt_gpg_sec_parms(sec_str, passphrase, salt, iv, sizeof(iv));

	struct sshbuf * seckey = sshbuf_new();
	sshbuf_putf(seckey, "(21:protected-private-key(3:rsa");
	sshbuf_putb(seckey, pub_parms);
	sshbuf_put(seckey, GPG_SEC_PARM_PREFIX, strlen(GPG_SEC_PARM_PREFIX));
	sshbuf_put(seckey, salt, sizeof(salt));
	sshbuf_putf(seckey, "8:%d)16:", S2K_ITER_BYTE_COUNT);
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
 *  Generate GPG keygrip for curve25519 key.
 *
 *  The GPG keygrip is a shortened representation (i.e. hash) of the parameters of the public key. The hash
 *  is just SHA1.
 *
 *  @param q Curve25519 public key
 *  @param q_len Num bytes in q
 *  @param grip Place to write keygrip. At least SHA_DIGEST_LENGTH bytes.
 */
static void
generate_gpg_curve25519_keygrip(const unsigned char * q, int q_len, unsigned char * grip)
{
	struct sshbuf * b = sshbuf_new();
	char buf[32];
	struct curve25519_param_entry * ptr = curve25519_param;
	int len;

	for (size_t ct = 0; ct < sizeof(curve25519_param) / sizeof(struct curve25519_param_entry); ct++) {
		len = snprintf(buf, sizeof(buf), "(1:%c%u:", ptr->param_name, ptr->len);
		buf[31] = '\0';
		sshbuf_put(b, buf, len);
		sshbuf_put(b, ptr->value, ptr->len);
		sshbuf_put_u8(b, ')');
		ptr++;
	}

	//  Can't use put_num_sexpr here, because in this context, GPG doesn't add the preceding 00 octet if the
	//  high bit of the first octet is set. Thanks for the consistency, GPG.
	//put_num_sexpr(b, q, q_len);
	sshbuf_putf(b, "(1:q%d:", q_len);
	sshbuf_put(b, q, q_len);
	sshbuf_put_u8(b, ')');
	compute_gpg_sha1_hash_sshbuf(b, grip);
}

/**
 *  Generate S-expression for Cv25519 public key parameter.
 *
 *  @param q Curve25519 public key
 *  @param q_len Num bytes in q
 *  @return sshbuf * S-expression. Caller should sshbuf_free
 */
static struct sshbuf *
generate_gpg_curve25519_pub_parms(const unsigned char * q, int q_len)
{
	struct sshbuf * pub_parms = sshbuf_new();
	sshbuf_put(pub_parms, GPG_PUB_PARM_PREFIX, strlen(GPG_PUB_PARM_PREFIX));
	put_num_sexpr(pub_parms, q, q_len);
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
generate_gpg_curve25519_sec_parms(const unsigned char * d, int d_len)
{
	struct sshbuf * sec_parms = sshbuf_new();
	sshbuf_put(sec_parms, "(1:d", 4);
	put_num_sexpr(sec_parms, d, d_len);
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
static struct sshbuf *
generate_gpg_curve25519_seckey(const unsigned char * q, int q_len, const unsigned char * d, int d_len,
		const unsigned char * passphrase)
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
	unsigned char * prefixed_q = malloc(q_len + 1);
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

	unsigned char hash[SHA_DIGEST_LENGTH];
	compute_gpg_sha1_hash_sshbuf(hash_str, hash);

	struct sshbuf * sec_str = sshbuf_new();
	sshbuf_put_u8(sec_str, '(');
	sshbuf_put_u8(sec_str, '(');
	sshbuf_putb(sec_str, sec_parms);
	sshbuf_put_u8(sec_str, ')');
	sshbuf_putf(sec_str, "(4:hash4:sha1%lu:", sizeof(hash));
	sshbuf_put(sec_str, hash, sizeof(hash));
	sshbuf_put_u8(sec_str, ')');
	sshbuf_put_u8(sec_str, ')');

	unsigned char salt[S2K_SALT_BYTES];
	unsigned char iv[GPG_SECKEY_IV_BYTES];
	struct sshbuf * enc_sec_parms = encrypt_gpg_sec_parms(sec_str, passphrase, salt, iv, sizeof(iv));

	struct sshbuf * seckey = sshbuf_new();
	sshbuf_putf(seckey, "(21:protected-private-key(3:ecc");
	sshbuf_putb(seckey, pub_parms);
	sshbuf_put(seckey, GPG_SEC_PARM_PREFIX, strlen(GPG_SEC_PARM_PREFIX));
	sshbuf_put(seckey, salt, sizeof(salt));
	sshbuf_putf(seckey, "8:%d)16:", S2K_ITER_BYTE_COUNT);
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
 *  padded out to a multiple of eight bytes, which means adding five bytes of 0x05 at the end.
 *
 *  @param sym_key_frame Place to write generated frame. Should point to at least AES256_KEY_BYTES + AES_WRAP_BLOCK_SIZE bytes
 *  @return int number of bytes in generated frame
 */
static int
generate_gpg_sym_key_frame(unsigned char * sym_key_frame)
{
	unsigned char * frame_ptr = sym_key_frame;
	*(frame_ptr++) = GPG_SKALGO_AES256;
	randombytes_buf(frame_ptr, AES256_KEY_BYTES);

	unsigned short cksum = 0;
	int i;
	for (i = 1; i <= AES256_KEY_BYTES; i++) {
		cksum += *(frame_ptr++);
	}
	*(frame_ptr++) = (cksum >> 8);
	*(frame_ptr++) = cksum;

	//  Add padding.
	for (i = 0; i < 5; i++) {
		*(frame_ptr++) = 0x05;
	}

	return (frame_ptr - sym_key_frame);
}

/**
 *  Create ephemeral (random) key pair and compute shared secret for recipient.
 *
 *  Choose an ephemeral Curve25519 key pair (random value for secret and the corresponding public point),
 *  then multiple the secret value by the recipient's public key. This is standard ECDH.
 *
 *  @param recip_pk Public Curve25519 key of recipient
 *  @param ephem_pk Place to write ephemeral public key. Should point to crypto_box_PUBLICKEYBYTES bytes
 *  @param secret Place to write shared secret. Should point to crypto_box_BEFORENMBYTES bytes
 */
static void
generate_curve25519_ephem_shared_secret(const unsigned char * recip_pk, unsigned char * ephem_pk,
										unsigned char *secret)
{
	unsigned char ephem_sk[crypto_box_SECRETKEYBYTES];

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
generate_curve25519_shared_secret(const unsigned char * sec_key, const unsigned char * pub_key,
								  unsigned char * secret)
{
	unsigned char tseckey[crypto_box_SECRETKEYBYTES];
	for (unsigned int i = 0; i < crypto_box_SECRETKEYBYTES; i++) {
		tseckey[i] = sec_key[crypto_box_SECRETKEYBYTES - 1 - i];
	}
	crypto_scalarmult_curve25519(secret, tseckey, pub_key);
}

/**
 *  Encrypt data from input file, write to output file.
 *
 *  Read input, hash/encrypt, and write encrypted data to output file. Reads in 8K chunks. After all input
 *  data is processed, there may be a partial block in the AES cipher.
 *
 *  @param infile File to read for input
 *  @param outfile File to which to write encrypted data
 *  @param sha_ctx SHA1 hash to update with input file data
 *  @param aes_ctx AES cipher to use to encrypt input file data
 *  @return int Num bytes read from input file
 */
static int
encrypt_input_file(FILE * infile, FILE * outfile, SHA_CTX * sha_ctx, EVP_CIPHER_CTX * aes_ctx)
{
#define CHUNK_SIZE 8 * 1024
	unsigned char * output = malloc(CHUNK_SIZE + 2 * AES_BLOCK_SIZE);
	unsigned char * input = malloc(CHUNK_SIZE);
	int             num_written;

	//  Now just read blocks of the input file, hash them, encrypt them, and output the encrypted data.
	int total_read = 0;
	int num_read = fread(input, 1, CHUNK_SIZE, infile);
	while (num_read > 0) {
		total_read += num_read;
		num_written = hashcrypt(sha_ctx, aes_ctx, input, num_read, output);
		if (num_written < 0 || (int) fwrite(output, 1, num_written, outfile) != num_written) {
			total_read = -1;
			break;
		}
		num_read = fread(input, 1, CHUNK_SIZE, infile);
	}

	free(output);
	free(input);
	return total_read;
}

/**
 *  Recover cv25519 secret key from encrypted data
 *
 *  Unencrypt the block containing the cv25519 secret key parameters, given the SSH RSA key (to generate
 *  the passphrase), the salt, and the IV. Then extract d, the secret key, from the S-expression.
 *
 *  @param enc_data Byte array containing encrypted key
 *  @param len Num bytes in enc_data
 *  @param ssh_key SSH RSA key used to protect the GPG key
 *  @param salt Byte array of random salt
 *  @param hash_bytes Num bytes to run through S2K hash to generate key
 *  @param iv Byte array containing initialization vector (should be GPG_SECKEY_IV_LEN bytes)
 *  @param d Place to write recovered secret key (should be crypto_box_SECRETKEYBYTES bytes)
 *  @return int Num bytes written to d
 */
static int
extract_curve25519_seckey(const unsigned char * enc_data, int len, const struct sshkey * ssh_key,
		const unsigned char * salt, int hash_bytes, const unsigned char * iv,
		unsigned char * d)
{
	//  First, generate the passphrase from the ssh key and generate the symmetric key from that.
	unsigned char sym_key[AES128_KEY_BYTES];

	char * passphrase = generate_gpg_passphrase_from_rsa(ssh_key);
	compute_gpg_s2k_key(passphrase, sizeof(sym_key), salt, hash_bytes, sym_key);
	free(passphrase);

	struct sshcipher_ctx ciphercontext;
	const struct sshcipher * cipher = cipher_by_name("aes128-cbc");
	int retval = cipher_init(&ciphercontext, cipher, sym_key, sizeof(sym_key), iv, GPG_SECKEY_IV_BYTES,
			CIPHER_DECRYPT);

	if (retval == 0) {
		unsigned char * output = malloc(len);
		retval = cipher_crypt(&ciphercontext, 0, output, enc_data, len, 0, 0);
		if (retval == 0) {
			assert(strncmp(output, "(((1:d", 6) == 0);
			unsigned char * ptr = output + 6;
			int len = strtoul(ptr, (char **) &ptr, 10);

			assert(*(ptr++) == ':');

			int pad_len = crypto_box_SECRETKEYBYTES - len;
			if (pad_len > 0) {
				memset(d, 0, pad_len);
			}

			memcpy(d + pad_len, ptr, len);
			retval = len;
		}

		free(output);
	}

	return retval;
}

/**
 *  Recover cv25519 secret key from S-expression
 *
 *  Finds the part of the S-expressoin containing the secret key, decrypts it, and recovers the key.
 *
 *  @param buf Byte array containing S-expression
 *  @param ssh_key RSA key used to protect GPG key
 *  @param d Place to write secret key (should be crypto_box_SECRETKEYBYTES bytes)
 *  @return int Num bytes written to d
 */
static int
get_gpg_curve25519_seckey(const unsigned char * buf, int buf_len, const struct sshkey * ssh_key, unsigned char * d)
{
	int retval = -1;
	size_t prefix_len = strlen(GPG_PUB_PARM_PREFIX);

	unsigned char * ptr = memmem(buf, buf_len, GPG_PUB_PARM_PREFIX, prefix_len);
	if (ptr != NULL) {
		ptr += prefix_len;
		int len = strtol(ptr, (char **) &ptr, 10);
		ptr++;  // Skip ':'
		assert(*ptr == GPG_ECC_PUBKEY_PREFIX);
		ptr += len;
		assert(*(ptr++) == ')');
		assert(strncmp(ptr, GPG_SEC_PARM_PREFIX, strlen(GPG_SEC_PARM_PREFIX)) == 0);
		ptr += strlen(GPG_SEC_PARM_PREFIX);
		//  Next grab the 8 byte salt for the SHA1 hash
		unsigned char salt[S2K_SALT_BYTES];
		memcpy(salt, ptr, sizeof(salt));
		ptr += sizeof(salt);

		//  Get the hash byte count - skip the "8:" preceding
		ptr += 2;
		int hash_bytes = strtol(ptr, (char **) &ptr, 10);
		assert(strncmp(ptr, ")16:", 4) == 0);
		ptr += 4;

		//  Grab the 16-byte IV for the encrypted key
		unsigned char iv[GPG_SECKEY_IV_BYTES];
		memcpy(iv, ptr, sizeof(iv));
		ptr += sizeof(iv);

		assert(*(ptr++) == ')');
		len = strtol(ptr, (char **) &ptr, 10);
		ptr++;  // Skip ':'

		assert(((ptr - buf) + len) < buf_len - 1);

		// ptr now points to the encrypted security parameters. Take that data, along with the necessary info
		// to decrypt, and get the private key d peeled out of it.
		retval = extract_curve25519_seckey(ptr, len, ssh_key, salt, hash_bytes, iv, d);

		ptr += len;
		assert(*ptr == ')');
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
static int
extract_ephemeral_key(const unsigned char * msg, const unsigned char ** ephem_pk)
{
	const unsigned char * msg_ptr = msg;
	int epk_len = (*msg_ptr << 8) + *(msg_ptr + 1);
	epk_len = (epk_len + 7) / 8;		//  Convert from bits to bytes
	msg_ptr += 2;
	assert(*msg_ptr == GPG_ECC_PUBKEY_PREFIX);
	msg_ptr++;
	epk_len--;
	assert(epk_len == crypto_box_PUBLICKEYBYTES);
	*ephem_pk = msg_ptr;
	msg_ptr += epk_len;
	return (msg_ptr - msg);
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
 *  @return Number of bytes processed from msg
 */
static int
extract_sym_key(const unsigned char * msg, const unsigned char * secret, const unsigned char * fp,
				unsigned char * sym_key)
{
	unsigned char kek[AES256_KEY_BYTES];
	unsigned char frame[AES256_KEY_BYTES + AES_WRAP_BLOCK_SIZE];

	generate_gpg_kek(fp, secret, kek);
	int enc_frame_len = *(msg++);
	int frame_len = decrypt_gpg_key_frame(msg, enc_frame_len, kek, frame);
	assert(frame_len == sizeof(frame));
	assert(*frame == GPG_SKALGO_AES256);
	memcpy(sym_key, frame + 1, AES256_KEY_BYTES);
	return enc_frame_len + 1;
}

/**
 *  Extract information from start of encrypted data packet.
 *
 *  Read the start of the packet from the file, get the SHA1 hash going, start decrypting, extract
 *  file name.
 *
 *  @param sha_ctx SHA1 hash of decrypted data 
 *  @param aes_ctx AES cipher to decrypt data
 *  @param infile File from which to read encrypted data
 *  @param output Place to store decrypted data (at least 528 bytes)
 *  @param fname Place to store name of the file that was encrypted (at least PATH_MAX + 1 bytes)
 *  @param num_dec Place to store number of bytes decrypted
 *  @param len Place to store remaining size of encrypted data to process
 *  @param extra Place to store number of bytes of trailing MDC packet that have already been read
 *  @return int Num bytes written to output array
 */
static int
process_enc_data_hdr(SHA_CTX * sha_ctx, EVP_CIPHER_CTX * aes_ctx, FILE * infile,
					 unsigned char * output, char * fname, int * num_dec, ssize_t * len, int * extra)
{
	//  More than enough space to get through all the header stuff and into the encrypted file data.
	unsigned char input[512];
	size_t num_read = fread(input, 1, sizeof(input), infile);
	assert(num_read >= 26);

	EVP_DecryptUpdate(aes_ctx, output, num_dec, input, num_read);
	assert(*num_dec > 18);
	assert(output[16] == output[14] && output[17] == output[15]);
	unsigned char * optr = output + 18;

	gpg_tag tag;
	int     tag_size_len = extract_tag_and_size(optr, &tag, len);
	optr += tag_size_len;
	assert(tag == GPG_TAG_LITERAL_DATA);
	assert(*(optr++) == 'b');	//	We always write literal data in "binary" format
	int fname_len = *(optr++);
	memcpy(fname, optr, fname_len);
	fname[fname_len] = '\0';
	optr += fname_len;

	time_t file_ts = 0;
	for (int i = 0; i < 4; i++, optr++) {
		file_ts = (file_ts << 8) + *optr;
	}

	*len -= fname_len + 1 /*format spec*/ + 1 /* fname len byte*/ + 4 /*timestamp*/;

	//  The rest of the encrypted data is the encrypted file data, followed by the
	//  MDC packet. Figure out how much of the current decrypted buffer is file data -
	//  part of it might be MDC packet.
	*num_dec -= (optr - output);
	SHA1_Update(sha_ctx, output, optr - output);

	if (*len < *num_dec) {  // At least part of MDC packet in buffer
		*extra = *num_dec - *len;
		*num_dec = *len;
	} else {
		*extra = 0;
	}

	return optr - output;
}

/**
 *  Read encrypted input, write encrypted output.
 *
 *  Read chunks from the file, decrypt them, and write the decrypted data to the output file until
 *  we have exhausted the literal data packet.
 *
 *  @param sha_ctx SHA1 hash of decrypted data 
 *  @param aes_ctx AES cipher to decrypt data
 *  @param infile File from which to read encrypted data
 *  @param outfile File to which to write decrypted data
 *  @param output Place to store decrypted data (at least CHUNK_SIZE + 2 * AES_BLOC_SIZE bytes)
 *  @param offset Offset into output buffer at which to start initially
 *  @param len Num bytes enc. data to process
 *  @param extra Num bytes of MDC packet already read
 *  @return int 0 if successful, negative number if error
 */
static int
process_enc_data(SHA_CTX * sha_ctx, EVP_CIPHER_CTX * aes_ctx, FILE * infile, FILE * outfile,
				 unsigned char * output, int offset, ssize_t len, int extra)
{
	int retval = -1;

	unsigned char input[CHUNK_SIZE];
	int num_dec;
	int num_read;
	unsigned char * optr = output + offset;

	while (len > 0) {
		num_read = fread(input, 1, sizeof(input), infile);
		EVP_DecryptUpdate(aes_ctx, output, &num_dec, input, num_read);

		optr = output;
		if (len < num_dec) {  // At least part of MDC packet in buffer
			extra = num_dec - len;
			optr += len;
			num_dec = len;
		} else {
			extra = 0;
			optr += num_dec;
		}

		fwrite(output, 1, num_dec, outfile);
		len -= num_dec;
		SHA1_Update(sha_ctx, output, num_dec);
		retval = 0;
	}

	//  When we get to here, we should have written the entire decrypted data file, and
	//  optr should point to the start of the MDC packet, if there was part of it in the
	//  last decrypted block. Read the rest of the MDC packet and validate the hash.
	num_read = fread(input, 1, sizeof(input), infile);

	if (extra > 0) {
		memmove(output, optr, extra);
		optr = output + extra;
	}
	EVP_DecryptUpdate(aes_ctx, optr, &num_dec, input, num_read);
	int last_dec;
	EVP_DecryptFinal_ex(aes_ctx, optr + num_dec, &last_dec);
	num_dec += last_dec;
	assert(extra + num_dec == GPG_MDC_PKT_LEN);

	SHA1_Update(sha_ctx, output, 2);
	unsigned char digest[SHA_DIGEST_LENGTH];
	SHA1_Final(digest, sha_ctx);

	if (memcmp(output + 2, digest, sizeof(digest)) == 0) {
		retval = 0;
	}
	return retval;
}


//================================================================================
//  GPG packet generation funcs
//================================================================================


/**
 *  Generate GPG public key packet.
 *
 *  Given an SSH key, create a GPG Public Key packet with the data from the SSH Key.
 *
 *  ** Currently only handles RSA keys.
 *
 *  @param ssh_key SSH RSA key
 *  @param msg Place to write packet
 */
static void
generate_gpg_public_key_packet(const struct sshkey * ssh_key, gpg_message * msg)
{
	msg->tag = GPG_TAG_PUBLIC_KEY;
	msg->data = sshbuf_new();

	sshbuf_put_u8(msg->data, GPG_KEY_VERSION);
	sshbuf_put_u32(msg->data, gpg_now);
	sshbuf_put_u8(msg->data, GPG_PKALGO_RSA_ES);
	put_bignum(msg->data, ssh_key->rsa->n);
	put_bignum(msg->data, ssh_key->rsa->e);
	msg->len = sshbuf_len(msg->data);
}

/**
 *  Generate GPG Subkey Packet for cv25519 key.
 *
 *  Format a GPG Subkey packet containing a cv25519 public key.
 *
 *  @param pub_key Byte array containing cv25519 public key
 *  @param pk_len Num bytes in pub_key
 *  @param msg Place to put generated packet
 */
static void
generate_gpg_curve25519_subkey_packet(const unsigned char * pub_key, size_t pk_len, gpg_message * msg)
{
	msg->tag = GPG_TAG_PUBLIC_SUBKEY;
	msg->data = sshbuf_new();

	sshbuf_put_u8(msg->data, GPG_KEY_VERSION);
	sshbuf_put_u32(msg->data, gpg_now);
	sshbuf_put_u8(msg->data, GPG_PKALGO_ECDH);		//  Curve25519 is an instance of ECDH
	sshbuf_put(msg->data, curve25519_oid, sizeof(curve25519_oid));

	/* A bit more GPG/libgcrypt fun - the public key parameter q needs to be prefixed by an octet that indicates
	 * that it is only the x coordinate. However, we need the unprefixed key for other uses, so we need to remember
	 * to add the prefix only in the necessary spots. Bad GPG! Anyway, create a separate copy of the parameter that
	 * includes the prefix to put into the public subkey packet.
	 */
	unsigned char * prefixed_pk = malloc(pk_len + 1);
	*prefixed_pk = GPG_ECC_PUBKEY_PREFIX;
	memcpy(prefixed_pk + 1, pub_key, pk_len);
	BIGNUM * pk = BN_new();
	BN_bin2bn(prefixed_pk, pk_len + 1, pk);
	put_bignum(msg->data, pk);
	BN_clear_free(pk);
	free(prefixed_pk);

	//  The last parameter specifies the hash algorithm and the encryption algorithm used to derive the key
	//  encryption key (KEK).
	sshbuf_put(msg->data, curve25519_kek_parm, sizeof(curve25519_kek_parm));
	msg->len = sshbuf_len(msg->data);
}

/**
 *  Generate GPG User ID packet.
 *
 *  @param user_id String identifying user (name and <email>, often)
 *  @param msg Place to put generated packet
 */
static void
generate_gpg_user_id_packet(const char * user_id, gpg_message * msg)
{
	msg->tag = GPG_TAG_USERID;
	msg->data = sshbuf_from(user_id, strlen(user_id));
	msg->len = sshbuf_len(msg->data);
}

/**
 *  Generate a Signature packet for given Public Key and UID packets.
 *
 *  Given an already generated public key (or public subkey) packet and UID packet, calculate the signature
 *  and format a Signature packet for it.
 *
 *  @param pubkey_pkt Public key or public subkey packet
 *  @param uid_pkt Following UID packet identifying key
 *  @param key RSA SSH key to use to sign
 *  @param sig_class class of signature to generate
 *  @param key_id Shorthand identifier for public key (tail end of keygrip)
 *  @param msg Place to write generated signature packet
 */
static void
generate_gpg_pk_uid_signature_packet(const gpg_message * pubkey_pkt, const gpg_message * uid_pkt,
									 const struct sshkey * key, int sig_class,
									 const unsigned char * key_id, gpg_message * msg)
{
	msg->tag = GPG_TAG_SIGNATURE;
	msg->data = sshbuf_new();

	sshbuf_put_u8(msg->data, GPG_KEY_VERSION);
	sshbuf_put_u8(msg->data, sig_class);
	sshbuf_put_u8(msg->data, GPG_PKALGO_RSA_ES);
	sshbuf_put_u8(msg->data, GPG_HASHALGO_SHA256);
	sshbuf_put_u16(msg->data, 24);  		//  Len of hashed subpackets
	sshbuf_put_u8(msg->data, 5);
	sshbuf_put_u8(msg->data, GPG_SIG_SUBPKT_SIGNATURE_CREATION_TIME);
	sshbuf_put_u32(msg->data, time(NULL));
	sshbuf_put_u8(msg->data, 5);
	sshbuf_put_u8(msg->data, GPG_SIG_SUBPKT_KEY_LIFETIME);
	sshbuf_put_u32(msg->data, 0);			// Does not expire
	sshbuf_put_u8(msg->data, 5);
	sshbuf_put_u8(msg->data, GPG_SIG_SUBPKT_PREF_SYM_ALGO);
	sshbuf_put_u8(msg->data, GPG_SKALGO_AES256);
	sshbuf_put_u8(msg->data, GPG_SKALGO_AES192);
	sshbuf_put_u8(msg->data, GPG_SKALGO_AES128);
	sshbuf_put_u8(msg->data, 0);
	sshbuf_put_u8(msg->data, 2);
	sshbuf_put_u8(msg->data, GPG_SIG_SUBPKT_KEY_FLAGS);
	if (pubkey_pkt->tag == GPG_TAG_PUBLIC_KEY) {
		sshbuf_put_u8(msg->data, 0x03);		// Sign + certify
	} else if (pubkey_pkt->tag == GPG_TAG_PUBLIC_SUBKEY) {
		sshbuf_put_u8(msg->data, 0x0c);		// encrypt
	}
	sshbuf_put_u8(msg->data, 2);
	sshbuf_put_u8(msg->data, GPG_SIG_SUBPKT_FEATURES);
	sshbuf_put_u8(msg->data, 0x01);			// enabled MDC - integrity protection for encrypted data packets

	SHA256_CTX  ctx;
	unsigned char buf[6];

	SHA256_Init(&ctx);

	/* The hash is computed over the entire public key packet, the entire UID packet (except the stupid length is
	 * expanded to four bytes), and the first part of the signature packet. It ends up with a trailer that is the
	 * version, 0xff, and the four-byte length of the hashed data, MSB first.
	 */

	/* First, generate the tag/length for the public key packet, hash that, then hash the packet contents. */
	int len = generate_tag_and_size(pubkey_pkt->tag, pubkey_pkt->len, buf);
	SHA256_Update(&ctx, buf, len);
	SHA256_Update(&ctx, sshbuf_ptr(pubkey_pkt->data), sshbuf_len(pubkey_pkt->data));

	/* Next, do the same with the UID packet, if there is one. Need to fiddle with the tag/length, because when
	 * GPG hashes it, it expands the length out to four bytes instead of one. Grr.
	 */
	if (uid_pkt != NULL) {
		buf[0] = 0xb4;   //  uid_pkt->tag converted to a tag byte
		buf[1] = 0x00;
		buf[2] = 0x00;
		buf[3] = 0x00;
		buf[4] = uid_pkt->len;
		SHA256_Update(&ctx, buf, 5);
		SHA256_Update(&ctx, sshbuf_ptr(uid_pkt->data), sshbuf_len(uid_pkt->data));
	}

	/* Now add the first part of the signature packet, through the hashed data section. */
	SHA256_Update(&ctx, sshbuf_ptr(msg->data), sshbuf_len(msg->data));

	/* Append the trailer to the hash. */
	int hash_len = sshbuf_len(msg->data);
	buf[0] = GPG_KEY_VERSION;
	buf[1] = 0xff;
	buf[2] = (unsigned char) ((hash_len >> 24) & 0xff);
	buf[3] = (unsigned char) ((hash_len >> 16) & 0xff);
	buf[4] = (unsigned char) ((hash_len >> 8) & 0xff);
	buf[5] = (unsigned char) (hash_len & 0xff);
	SHA256_Update(&ctx, buf, 6);

	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256_Final(digest, &ctx);

	/* Add the unhashed subpackets to the signature packet now. Currently, just the issuer subpacket. */
	sshbuf_put_u16(msg->data, 10); //  Len of unhashed subpackets
	sshbuf_put_u8(msg->data, 9);
	sshbuf_put_u8(msg->data, GPG_SIG_SUBPKT_ISSUER);
	sshbuf_put(msg->data, key_id, 8);

	/* Tack on the first two bytes of the hash value, for error detection. */
	sshbuf_put_u8(msg->data, digest[0]);
	sshbuf_put_u8(msg->data, digest[1]);

	/* Now compute the RSA signature of the hash - m^d mod n, where m is the message (the hash), d is the
	 * private key, and n is the modulus. This MPI goes into the signature packet (with the normal two-octet
	 * length prefix).
	 */
	BIGNUM * sig = compute_rsa_signature(digest, SHA256_DIGEST_LENGTH, key);
	put_bignum(msg->data, sig);
	BN_clear_free(sig);
	msg->len = sshbuf_len(msg->data);
}

/**
 *  Generate a GPG Trust packet.
 *
 *  @param msg Place to write generated packet
 */
static void
generate_gpg_trust_packet(gpg_message * msg)
{
	msg->tag = GPG_TAG_TRUST;
	msg->data = sshbuf_new();
	msg->len = 2;
	sshbuf_put_u8(msg->data, 0);
	sshbuf_put_u8(msg->data, 3);
}

/**
 *  Create Public Key Encrypted Symmetric Key packet.
 *
 *  Create a GPG Public Key Encrypted Symmetric Key packet. This packet holds the randomly chosen symmetric
 *  key, encrypted to one of the recipients using a public key algorithm.
 *
 *  First, we use Curve25519 to create a shared secret between sender and recipient. GPG uses an ephemeral
 *  key pair instead of the sender's private key to compute the shared secret, so we generate a Curve25519
 *  key pair. Then we run Curve25519 with that private key and the recipient's public key to create a shared
 *  secret.
 *
 *  Next, GPG uses that shared key to derive *yet another* key, the key encryption key (kek). We do the
 *  same thing, then use that key in AES128 to encrypt the key frame. Once the key frame is encrypted to the
 *  recipient, we dump it into the PKESK packet, along with the public portion of the ephemeral key pair we
 *  generated.
 *
 *  @param key Pointer to struct containing recipient's pubic key and associated info
 *  @param sym_key_frame Random symmetric key with wrapping
 *  @param frame_len Num bytes in sym_key_frame
 *  @param msg Place to write generated packet
 *  @return 0 if successful, negative number if error
 */
static int
generate_gpg_pkesk_packet(const gpg_public_key * key, unsigned char * sym_key_frame, int frame_len, 
						  gpg_message * msg)
{
	int retval = -1;

	msg->tag = GPG_TAG_PKESK;
	msg->data = sshbuf_new();

	sshbuf_put_u8(msg->data, GPG_PKESK_VERSION);
	sshbuf_put(msg->data, key->fp + (GPG_KEY_FP_LEN - GPG_KEY_ID_LEN), GPG_KEY_ID_LEN);
	sshbuf_put_u8(msg->data, GPG_PKALGO_ECDH);		//  Algorithm used to encrypt symmetric key

	unsigned char secret[crypto_box_BEFORENMBYTES];
	unsigned char ephem_pk[crypto_box_PUBLICKEYBYTES + 1];
	generate_curve25519_ephem_shared_secret(key->key, ephem_pk + 1, secret);
	ephem_pk[0] = GPG_ECC_PUBKEY_PREFIX;			//  Indicates that it is on the X value, not the complete point

	unsigned char kek[AES128_KEY_BYTES];
	generate_gpg_kek(key->fp, secret, kek);

	//  We are going to encrypt the sym. key frame using AES128-WRAP. This requires that the frame be a multiple
	//  of the block size (8), which it is. The encryption will add one more block on the end of the encrypted
	//  data.
	//  Also leave an extra byte at the beginning to hold the encrypted frame length.
	unsigned char * enc_frame = malloc(frame_len + 2 * AES_WRAP_BLOCK_SIZE + 1);
	int enc_frame_len = encrypt_gpg_key_frame(sym_key_frame, frame_len, kek, enc_frame + 1);
	if (enc_frame_len > 0) {
		*enc_frame = (unsigned char) enc_frame_len;
		enc_frame_len++;

		//  Write the ephemeral PK first, prefixed with the two-byte length in bits.
		//  Then write the encrypted frame without a length prefix.
		sshbuf_put_u16(msg->data, crypto_box_PUBLICKEYBYTES * 8 + 7);
		/*
		   unsigned char z[33];
		   z[0] = ephem_pk[0];
		   for (int ct = 1; ct<33; ct++) z[ct] = ephem_pk[33-ct];
		   sshbuf_put(msg->data, z, 33);
		   */
		sshbuf_put(msg->data, ephem_pk, sizeof(ephem_pk));
		sshbuf_put(msg->data, enc_frame, enc_frame_len);
		msg->len = sshbuf_len(msg->data);
		retval = 0;
	}

	return retval;
}

/**
 *  Generate the start of the literal data packet.
 *
 *  Generate the preliminary info that will be written to the literal data packet, according to the PGP
 *  standard.
 *
 *  @param fname Name of output file - we strip any preceding path from it
 *  @param file_len Num bytes in file that will be placed into literal data packet (limit 2^31 currently)
 *  @param mod_time Last modification time of file
 *  @param data_pkt_hdr Place to write generated packet. Should be at least 12 + fname length bytes
 *  @return int Num bytes in data_pkt_hdr
 */
static int
generate_gpg_literal_data_packet(const char * fname, size_t file_len, time_t mod_time,
								 unsigned char * data_pkt_hdr)
{
	//  We only put the base file name into the packet - strip the path before doing anything with it.
	char * tmp_name = strdup(fname);
	char * base_ptr = basename(tmp_name);

	//  Determine size of inner Literal Data Packet
	unsigned char literal_hdr[6];
	int data_len = file_len + 4 /*timestamp*/ + strlen(base_ptr) + 1 /*fname len*/ + 1 /*data fmt*/;
	int literal_hdr_len = generate_tag_and_size(GPG_TAG_LITERAL_DATA, data_len, literal_hdr);

	unsigned char * dptr = data_pkt_hdr;
	memcpy(dptr, literal_hdr, literal_hdr_len);
	dptr += literal_hdr_len;
	*(dptr++) = 'b';   //  Indicates "binary" data, no CR-LF conversion
	*(dptr++) = strlen(base_ptr);	//  Precede name by its length, in one byte
	strcpy(dptr, base_ptr);
	dptr += strlen(base_ptr);
	*(dptr++) = mod_time >> 24;
	*(dptr++) = mod_time >> 16;
	*(dptr++) = mod_time >>  8;
	*(dptr++) = mod_time;

	free(tmp_name);

	return dptr - data_pkt_hdr;
}


/**
 *  Generate and write Modification Detection Code packet.
 *
 *  Generate a PGP Modification Detection Code (MDC) packet and write it to the output file.
 *  This will finalize the SHA1 hash and the AES cipher that are provided.
 *
 *  @param outfile File to which to write packet
 *  @param sha_ctx SHA1 hash of input data processed so far
 *  @param aes_ctx AES cipher to encrypt MDC packet before writing
 *  @return int 0 if successful, negative number if error
 */
static int
write_gpg_mdc_packet(FILE * outfile, SHA_CTX * sha_ctx, EVP_CIPHER_CTX * aes_ctx)
{
	int retval = -1;
	//  We hash the header of the MDC packet into the MDC hash, then the hash is finalized and becomes
	//  the body of the MDC packet. The MDC packet is encrypted, and the AES encryption is finalized
	//  and output.
	unsigned char input[SHA_DIGEST_LENGTH + 2];
	input[0] = 0xd3;		//  The formatted tag of the Modification Detection Code (MDC) packet
	input[1] = 0x14;		//  The length of the MDC packet

	SHA1_Update(sha_ctx, input, 2);
	SHA1_Final(input + 2, sha_ctx);

	unsigned char output[2 * AES_BLOCK_SIZE];
	int num_written;
	EVP_EncryptUpdate(aes_ctx, output, &num_written, input, sizeof(input));

	int final_written;
	EVP_EncryptFinal_ex(aes_ctx, output + num_written, &final_written);
	num_written += final_written;
	if ((int) fwrite(output, 1, num_written, outfile) == num_written) {
		retval = 0;
	}

	return retval;
}


//================================================================================
//  GPG packet retrieval funcs
//================================================================================


/**
 *  Read public key packet from file.
 *
 *  @param infile File from which to read
 *  @return gpg_message containing packet, or NULL if error. Caller should sshbuf_free msg->data, free msg
 */
static gpg_message *
get_pub_key_packet(FILE * infile)
{
	gpg_tag tag = GPG_TAG_DO_NOT_USE;
	size_t len;

	gpg_message * msg = NULL;
	get_tag_and_size(infile, &tag, &len);
	if (tag == GPG_TAG_PUBLIC_KEY) {
		unsigned char * key = malloc(len);
		if (fread(key, 1, len, infile) == (size_t) len) {
			msg = malloc(sizeof(gpg_message));
			msg->tag = tag;
			msg->len = len;
			msg->data = sshbuf_from(key, len);
		} else {
			free(key);
		}
	}

	return msg;
}

/**
 *  Read subkey packet from file.
 *
 *  @param infile File from which to read
 *  @return gpg_message containing packet, or NULL if error. Caller should sshbuf_free msg->data, free msg
 */
static gpg_message *
get_curve25519_key_packet(FILE * infile)
{
	gpg_tag tag = GPG_TAG_DO_NOT_USE;
	size_t len;

	gpg_message * msg = NULL;
	unsigned char * subkey = NULL;

	do {
		get_tag_and_size(infile, &tag, &len);
		if (tag != GPG_TAG_PUBLIC_SUBKEY) {
			fseek(infile, len, SEEK_CUR);
		} else {
			subkey = malloc(len);
			if (fread(subkey, 1, len, infile) != (size_t) len) {
				free(subkey);
				subkey = NULL;
			}
		}
	} while (!feof(infile) && tag != GPG_TAG_PUBLIC_SUBKEY);

	if (tag == GPG_TAG_PUBLIC_SUBKEY && subkey != NULL) {
		//  Make sure it's a curve22519 subkey. Shouldn't be anything else in the file, but just make sure.
		if (subkey[5] != GPG_PKALGO_ECDH ||
				memcmp(subkey + 6, curve25519_oid, sizeof(curve25519_oid)) != 0) {
			//  Nope - different subkey. Throw the packet away and try again.
			free(subkey);
			msg = get_curve25519_key_packet(infile);
		} else {
			msg = malloc(sizeof(gpg_message));
			msg->tag = tag;
			msg->len = len;
			msg->data = sshbuf_from(subkey, len);
		}
	}

	return msg;
}

/**
 *  Read the public encryption subkey for the specified user from the user's ~/.ssh/pubkey.gpg file.
 *
 *  Read the start of the input file, which should be a sequence of Public Key Encrypted Symmetric Key packets.
 *  Look for the one that matches the provided key ID. If found, recover the PKESK packet. Continue reading
 *  until all PKESK packets are read from the file.
 *
 *  @param infile File from which to read packet
 *  @param key_id ID of user's public key
 *  @param msg Place to write PKESK packet if found
 *  @param next_tag Tag of next packet found after last PKESK packet
 *  @param next_len Length of next packet found after last PKESK packet
 *  @return int 0 if successful, negative number if error
*/
static int
get_gpg_pkesk_packet(FILE * infile, const char * key_id, unsigned char * msg, gpg_tag * next_tag, int * next_len)
{
	int retval = -1;

	gpg_tag tag = GPG_TAG_DO_NOT_USE;
	size_t len;

	get_tag_and_size(infile, &tag, &len);
	while (tag == GPG_TAG_PKESK && !feof(infile)) {
		unsigned char pkt_start[GPG_KEY_ID_LEN + 1];
		if (fread(pkt_start, 1, sizeof(pkt_start), infile) == sizeof(pkt_start)) {
			size_t left_to_read = len - (GPG_KEY_ID_LEN + 1);
			if (memcmp(key_id, pkt_start + 1, GPG_KEY_ID_LEN) == 0) {
				if (fread(msg, 1, left_to_read, infile) == left_to_read) {
					retval = 0;
				} else {
					retval = -1;
					break;
				}
			} else {
				if (fseek(infile, left_to_read, SEEK_CUR) != 0) {
					retval = -1;
					break;
				}
			}
		} else {
			break;
		}
		get_tag_and_size(infile, &tag, &len);
	}

	if (!feof(infile)) {
		*next_tag = tag;
		*next_len = len;
	}

	return retval;
}


//================================================================================
//  GPG file manipulation funcs
//================================================================================


/**
 *  Open the file containing the RSA secret key.
 *
 *  Requires computing the keygrip of the public key.
 *
 *  @param seckey_dir Path in which to look for file
 *  @param ssh_key RSA key (only need public portion)
 *  @return FILE * File containing RSA secret key, opened for write
 */
static FILE *
open_rsa_seckey_file(const char * seckey_dir, const struct sshkey * ssh_key)
{
	unsigned char keygrip[SHA_DIGEST_LENGTH];
	char hexgrip [2 * SHA_DIGEST_LENGTH + 1];

	unsigned char tmp_n[1025];
	unsigned char * tmp_ptr;
	tmp_n[0] = 0x00;
	int n_len = BN_bn2bin(ssh_key->rsa->n, tmp_n + 1);
	if (tmp_n[1] > 0x7f) {
		n_len++;
		tmp_ptr = tmp_n;
	} else {
		tmp_ptr = tmp_n + 1;
	}

	//  So much simpler than the curve25519 keygrip - an RSA keygrip is just a SHA1 hash of the public key
	//  parameter n.
	compute_gpg_sha1_hash_chars(tmp_n, n_len, keygrip);
	hex2str(keygrip, sizeof(keygrip), hexgrip);

	char dir_name[512];
	FILE * infile = NULL;

	int len = snprintf(dir_name, sizeof(dir_name), "%s/%s.key", seckey_dir, hexgrip);

	if (len < (int) sizeof(dir_name)) {
		infile = fopen(dir_name, "w");
	}
	return infile;
}

/**
 *  Open the file containing the cv25519 secret key.
 *
 *  Requires computing the keygrip of the public key.
 *
 *  @param seckey_dir Path in which to look for file
 *  @param mode String specifying mode for fopen()
 *  @param q Cv25519 public key
 *  @param q_len Num bytes in q
 *  @return FILE * File containing cv25519 secret key, opened for write
 */
static FILE *
open_curve25519_seckey_file(const char * seckey_dir, const char * mode, const unsigned char * q, int q_len)
{
	unsigned char keygrip[SHA_DIGEST_LENGTH];
	char hexgrip [2 * SHA_DIGEST_LENGTH + 1];

	generate_gpg_curve25519_keygrip(q, q_len, keygrip);
	hex2str(keygrip, sizeof(keygrip), hexgrip);

	char fname[512];
	FILE * infile = NULL;

	int len = snprintf(fname, sizeof(fname), "%s/%s.key", seckey_dir, hexgrip);

	if (len < 512) {
		infile = fopen(fname, mode);
	}
	return infile;
}

/**
 *  Attempt to open an output file to hold encrypted data.
 *
 *  For an input path, generate an associated file name for the output (by appending ".iron"). Make sure
 *  that file can be overwritten if it exists, then open the file in "w+" mode.
 *
 *  @param fname Name of input file
 *  @param enc_fname Output - name of associated output file. Should point to at least PATH_MAX + 1 chars
 *  @return FILE * NULL if unsuccessful, pointer to open file otherwise
 */
static FILE *
open_encrypted_output_file(const char * fname, char * enc_fname)
{
	strcpy(enc_fname, fname);
	strcat(enc_fname, ICL_SECURE_FILE_SUFFIX);

	FILE * out_file;
	if (check_write_allowed(enc_fname)) {
		out_file = fopen(enc_fname, "w+");
	} else {
		out_file = NULL;
	}

	return out_file;
}

/**
 *  Open file to which to write decrypted data.
 *
 *  Given then name of the file into which to write data and the path to the encrypted file, generate path
 *  to which to write decrypted data. If this path is the same as the path of the encrypted file, fail.
 *  If the output file already exists, prompt user to confirm overwrite.
 *
 *  @param fname Name of output file to create
 *  @param local_path Path of input file
 *  @param dec_fname Place to write name of output file. Should be at least PATH_MAX + 1 bytes
 *  @return FILE * Opened output file, NULL if unable to open for output.
 */
static FILE *
open_decrypted_output_file(const char * fname, const char * local_path, char * dec_fname)
{
	FILE * out_file = NULL;
	char path[PATH_MAX + 1];
	strncpy(path, local_path, PATH_MAX);
	path[PATH_MAX] = '\0';
	char * dir = dirname(path);

	if (strcmp(dir, ".") == 0 && strncmp(fname, "./", 2) != 0) {
		strncpy(dec_fname, fname, PATH_MAX);
	} else {
		snprintf(dec_fname, PATH_MAX, "%s/%s", dir, fname);
	}
	dec_fname[PATH_MAX] = '\0';

	if (strcmp(dec_fname, local_path) == 0) {
		logit("Cannot unlock file - unlocked file name is the same as the locked file name.");
	} else if (check_write_allowed(dec_fname)) {
		out_file = fopen(dec_fname, "w+");
	}

	return out_file;
}

/**
 *  Write GPG pubring.gpg file.
 *
 *  Assemble the packets for the user's public RSA key, UID, signature, public cv25519 subkey, UID, and
 *  signature into a pubring.gpg file in user's .ssh directory.
 *
 *  @param pub_file File to which to write packets
 *  @param ssh_key User's SSH RSA key
 *  @param pub_subkey User's cv25519 public key
 *  @param uid String identifying user (name <emailaddr>, typically)
 *  @param key_fp Place to write fingerprint of the public RSA key. (At least GPG_KEY_FP_LEN bytes)
 *  @param subkey_fp Place to write fingerprint of the public cv25519 key. (At least GPG_KEY_FP_LEN bytes)
 *  @return int 0 if successful, negative number if error
 */
static int
write_public_key_file(FILE * pub_file, const struct sshkey * ssh_key, const unsigned char * pub_subkey,
					  const char * uid, unsigned char * key_fp, unsigned char * subkey_fp)
{
	int retval = -1;
	gpg_message public_key_pkt;
	gpg_message user_id_pkt;
	gpg_message sig_pkt;
	gpg_message trust_pkt;

	generate_gpg_public_key_packet(ssh_key, &public_key_pkt);
	compute_gpg_key_fingerprint(&public_key_pkt, key_fp);
	unsigned char * key_id = key_fp + GPG_KEY_ID_OFFSET;  //  Last 8 bytes of fingerprint

	generate_gpg_user_id_packet(uid, &user_id_pkt);
	generate_gpg_pk_uid_signature_packet(&public_key_pkt, &user_id_pkt, ssh_key, GPG_SIGCLASS_POSITIVE_CERT,
			key_id, &sig_pkt);
	generate_gpg_trust_packet(&trust_pkt);

	retval = put_gpg_message(pub_file, &public_key_pkt);

	if (retval == 0) {
		retval = put_gpg_message(pub_file, &user_id_pkt);
		if (retval == 0) {
			retval = put_gpg_message(pub_file, &sig_pkt);
			if (retval == 0) {
				retval = put_gpg_message(pub_file, &trust_pkt);
			}
		}
	}
	sshbuf_free(public_key_pkt.data);
	sshbuf_free(user_id_pkt.data);
	sshbuf_reset(sig_pkt.data);

	/* Now add the subkey for the new curve25519 key */
	if (retval == 0) {
		gpg_message public_subkey_pkt;
		generate_gpg_curve25519_subkey_packet(pub_subkey, crypto_box_PUBLICKEYBYTES, &public_subkey_pkt);
		compute_gpg_key_fingerprint(&public_subkey_pkt, subkey_fp);
		generate_gpg_pk_uid_signature_packet(&public_subkey_pkt, NULL, ssh_key, GPG_SIGCLASS_SUBKEY_BIND,
				key_id, &sig_pkt);

		retval = put_gpg_message(pub_file, &public_subkey_pkt);

		if (retval == 0) {
			retval = put_gpg_message(pub_file, &sig_pkt);
			if (retval == 0) {
				retval = put_gpg_message(pub_file, &trust_pkt);
			}
		}
		sshbuf_free(public_subkey_pkt.data);
		sshbuf_free(sig_pkt.data);
		sshbuf_free(trust_pkt.data);
	}

	return retval;
}

/**
 *  Write the files containing RSA secret key and cv25519 secret key.
 *
 *  Generates the contents of each of the files and writes it to the private key subdirectory of the user's
 *  .ssh directory. Files are named with the keygrip of the key. The secret key parameter portions of the files
 *  are encrypted, using the supplied passphrase to generate the key.
 *
 *  @param ssh_dir Path to the user's .ssh directory (usually under ~<login>)
 *  @param ssh_key RSA key, both public and secret parts
 *  @param q Cv25519 public key
 *  @param q_len num bytes in q
 *  @param d Cv25519 secret key
 *  @param d_len num bytes in d
 *  @return int 0 if successful, negative number if error
 */
static int
write_secret_key_files(const char * ssh_dir, const struct sshkey * ssh_key, const unsigned char * q, int q_len,
		   			   const unsigned char * d, int d_len, const char * passphrase)
{
	int retval = -1;
	char * seckey_dir = check_seckey_dir(ssh_dir);

	if (seckey_dir) {
		FILE * rsa_key_file = open_rsa_seckey_file(seckey_dir, ssh_key);

		if (rsa_key_file != NULL) {
			struct sshbuf * rsa_seckey = generate_gpg_rsa_seckey(ssh_key, passphrase);
			if (fwrite(sshbuf_ptr(rsa_seckey), 1, sshbuf_len(rsa_seckey), rsa_key_file) == sshbuf_len(rsa_seckey)) {
				FILE * c_key_file = open_curve25519_seckey_file(seckey_dir, "w", q, q_len);
				if (c_key_file != NULL) {
					struct sshbuf * c_seckey = generate_gpg_curve25519_seckey(q, q_len, d, d_len, passphrase);
					if (fwrite(sshbuf_ptr(c_seckey), 1, sshbuf_len(c_seckey), c_key_file) == sshbuf_len(c_seckey)) {
						retval = 0;
					}
					sshbuf_free(c_seckey);
					fclose(c_key_file);
				}
				sshbuf_free(rsa_seckey);
				fclose(rsa_key_file);
			}
		}
		free(seckey_dir);
	}
	return retval;
}

/**
 *  Write a line to the user's .pubkey file containing specified key info.
 *
 *  Write the key name, public key, fingerprint, and UID in one line to the file.
 *
 *  @param outfile File to which to write line
 *  @param key_name Name used to identify key (e.g. "rsa", "cv25519"). Will be prefixed by "iron-"
 *  @param key Public key to write as hex string
 *  @param len Num bytes in key
 *  @param fp Byte array containing key fingerprint. Converted to hax string
 *	@param uid String identifying user (typically "Name <emailaddr>")
 *  @return int 0 if successful, negative number if error
 */
static int
write_key_to_pubkey(FILE * outfile, const char * key_name, const unsigned char * pub_key, int len,
					const unsigned char * fp, const char * uid)
{
	int retval = -1;

	unsigned char tmp[2 * GPG_MAX_KEY_SIZE + 1];
	hex2str(pub_key, len, tmp);
	if (fprintf(outfile, "iron-%s: %s ", key_name, tmp) > 0) {
		hex2str(fp, GPG_KEY_FP_LEN, tmp);
		if (fprintf(outfile, "%s %s\n", tmp, uid) > 0) {
			retval = 0;
		}
	}
	return retval;
}

/**
 *  Write RSA and cv25519 key entries to .pubkey file for login.
 *
 *  If file already exists, create new file that contains all lines that don't start with "iron-",
 *  then write lines for RSA key and cv25519 key. If file doesn't exist, create new one with those
 *  two entries.
 *
 *  @param login Login of user for which to write .pubkey
 *  @param ssh_key Params of RSA key to write to file (only need public param n)
 *  @param pub_key Public cv25519 key
 *	@param uid String identifying user (typically "Name <emailaddr>")
 *	@param key_fp Byte array containing fingerprint for RSA key
 *	@param subkey_fp Byte array containing fingerprint for cv25519 key
 *  @return int 0 if successful, negative number if error
 */
static int
write_pubkey_file(const char * login, struct sshkey * ssh_key, const unsigned char * pub_key,
				  const char * uid, const unsigned char * key_fp, const unsigned char * subkey_fp)
{
	int retval = -1;

	char fname[PATH_MAX + 1];
	struct passwd * pw = getpwnam(login);
	if (pw != NULL) {
		snprintf(fname, PATH_MAX, "%s/.pubkey", pw->pw_dir);
		fname[PATH_MAX] = '\0';

		FILE * outfile = NULL;
		int shuffle_files;
		char tname[PATH_MAX + 1];
		FILE * infile;

		if (access(fname, F_OK) == 0) {
			//  File already exists - copy all the non-IronCore lines from it to a new file
			shuffle_files = 1;
			infile = fopen(fname, "r");
			if (infile != NULL) {
				snprintf(tname, PATH_MAX, "%s/.pubkey.XXXXXX", pw->pw_dir);
				tname[PATH_MAX] = '\0';
				mktemp(tname);
				outfile = fopen(tname, "w");
				if (outfile != NULL) {
					char line[3000];
					while (fgets(line, sizeof(line), infile)) {
						if (strncmp(line, "iron-", 5) != 0) {
							fputs(line, outfile);
						}
					}
				}
			}
		} else {
			//  Starting with a fresh file
			shuffle_files = 0;
			outfile = fopen(fname, "w");
		}

		if (outfile != NULL) {
			unsigned char tmp[GPG_MAX_KEY_SIZE];
			int len = BN_bn2bin(ssh_key->rsa->n, tmp);
			if (write_key_to_pubkey(outfile, "rsa", tmp, len, key_fp, uid) == 0) {
				if (write_key_to_pubkey(outfile, "cv25519", pub_key, crypto_box_PUBLICKEYBYTES, subkey_fp,
						   				uid) == 0) {
					fchmod(fileno(outfile), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

					if (shuffle_files) {
						fclose(infile);
						unlink(fname);
						rename(tname, fname);
					}
					retval = 0;
				}
			}
		}
	}

	return retval;
}

/**
 *  Create new GPG key files for use by ironsftp.
 *
 *  Randomly generate a curve25519 key pair, then create a new GPG-compatible public key file containing the
 *  SSH key (currently only RSA keys supported) as the "signing key" and the curve25519 key as a subkey. This
 *  file is written to ~<login>/.ssh/pubkey.gpg. Also create ~<login>/.ssh/trustdb.gpg, a file that records
 *  trust in public keys. 
 *
 *  Once the public key file is created, create two of the GPG-compatible new-format secret key files, one for
 *  the RSA key and one for the curve25519 subkey, in a private-keys-v1.d subdirectory under ~<login>/.ssh.
 *
 *  In order to protect the secret parameters in the secret key files, we need a passphrase, and we don't have
 *  access to the passphrase from the SSH key file, so we generate a new passphase using the secret key params
 *  from the SSH key.
 *
 *  @param ssh_dir Path to the ~<login>/.ssh directory where we will store the generated files
 *  @param login Login of the user - most likely the user running the executable
 *  @return int 0 if successful, -1 if error
 */
static int
generate_iron_keys(const char * const ssh_dir, const char * const login)
{
	int retval = -1;
	if (ssh_dir != NULL && *ssh_dir) {
		unsigned char pub_key[crypto_box_PUBLICKEYBYTES];
		unsigned char sec_key[crypto_box_SECRETKEYBYTES];
		crypto_box_keypair(pub_key, sec_key);
		clamp_and_reverse_seckey(sec_key);

		struct sshkey * ssh_key;
		char * comment;

		if (retrieve_ssh_key(ssh_dir, &ssh_key, &comment) == 0) {
			char file_name[PATH_MAX + 1];
			snprintf(file_name, PATH_MAX, "%s%s", ssh_dir, GPG_PUBLIC_KEY_FNAME);
			file_name[PATH_MAX] = '\0';
			FILE * pub_file = fopen(file_name, "w");
			if (pub_file != NULL) {
				unsigned char key_fp[GPG_KEY_FP_LEN];
				unsigned char subkey_fp[GPG_KEY_FP_LEN];

				fchmod(fileno(pub_file), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

				const char * uid;

				//  If the ssh key file contained a comment, it was probably the user name / email address.
				//  Use that for the GPG UID packet. Otherwise, just use the login - best we can do.
				if (comment && *comment) {
					uid = comment;
				} else {
					uid = login;
				}

				if (write_public_key_file(pub_file, ssh_key, pub_key, uid, key_fp, subkey_fp) == 0) {
					char * passphrase = generate_gpg_passphrase_from_rsa(ssh_key);
					if (write_secret_key_files(ssh_dir, ssh_key, pub_key, sizeof(pub_key), sec_key,
								sizeof(sec_key), passphrase) == 0) {
						printf("\nGenerated new GPG secret keys with the passphrase %s\n\n", passphrase);
						free(passphrase);

						if (write_trustdb_file(ssh_dir, key_fp, sizeof(key_fp), uid) == 0 ) {
							if (write_pubkey_file(login, ssh_key, pub_key, uid, key_fp, subkey_fp) == 0) {
								retval = 0;
							}
						}
					}
				}
				fclose(pub_file);
			} else {
				logit("Unable to open %s to write public key.", file_name);
			}
		}
	}

	return retval;
}

/**
 *  Encrypt actual file data into output file.
 *
 *  Encrypt the actual file data, using the symmetric key we generated and encrypted. This is a multi-step process:
 *    1. Place data into a Literal Data Packet.
 *    2. [optional] Generate a Compressed Data Packet containing the compressed Literal Data Packet
 *    3. Prefix this data packet with 16 bytes of random data, then 2 bytes that repeat the last of those 16 bytes.
 *    4. Append a Modification Detection Code Packet, which is a SHA1 hash of the data from 3 plus the first two
 *       bytes of the MDC packet (0xd314)
 *    4. Encrypt
 *    5. Place into a Symmetrically Encrypted and Protected Data Packet.
 *
 *  For now, we skip compression and just stuff the data into a literal data packet. We also limit the size of
 *  files we handle to 2^32 - 1024 bytes, so we can fit each packet length into four bytes.
 *
 *  @param infile File from which to read data
 *  @param fname Path of input file
 *  @param outfile File to which to write encrypted data
 *  @param sym_key Randomly generated symmetric key to used to encrypt data. Should be AES256_KEY_BYTES
 *  @return int 0 if successful, negative number if error
 */
static int
write_encrypted_data_file(FILE * infile, const char * fname, FILE * outfile, unsigned char * sym_key)
{
	int retval = -1;

	//  Set up the SHA1 hash that will accumulate the literal data and generate the MDC packet at the end.
	SHA_CTX sha_ctx;
	SHA1_Init(&sha_ctx);

	//  Set up the AES256 cipher to encrypt the literal data
	EVP_CIPHER_CTX aes_ctx;
	const EVP_CIPHER * aes_cipher = EVP_aes_256_cfb();
	EVP_CIPHER_CTX_init(&aes_ctx);
	if (EVP_EncryptInit_ex(&aes_ctx, aes_cipher, NULL /* dflt engine */, sym_key, NULL /* dflt iv */)) {
		//  First output the start of the Symmetrically Encrypted Integrity Protected Data Packet.
		//  This requires that we know how long the data packet will be, so retrieve the file size,
		//  then write the SEIPD packet header using that length.
		struct stat statstr;
		fstat(fileno(infile), &statstr);

		unsigned char data_pkt_hdr[128];
		int data_pkt_hdr_len = generate_gpg_literal_data_packet(fname, statstr.st_size, statstr.st_mtime,
				data_pkt_hdr);

		//  Add size of random data prefix and MDC packet and version # prefix
		int data_len = data_pkt_hdr_len + statstr.st_size +
			AES_BLOCK_SIZE + 2 /*prefix*/ + 22 /*MDC*/ + 1 /*version*/;

		unsigned char seipd_hdr[7];
		int seipd_hdr_len = generate_tag_and_size(GPG_TAG_SEIP_DATA, data_len, seipd_hdr);

		seipd_hdr[seipd_hdr_len] = GPG_SEIPD_VERSION;
		seipd_hdr_len++;

		//  Start emitting the SEIP packet.
		fwrite(seipd_hdr, 1, seipd_hdr_len, outfile);

		//  From this point, everything is hashed and encrypted. Start with the random prefix bytes, then the
		//  last two bytes repeated.
		unsigned char input[128];
		unsigned char output[128];
		randombytes_buf(input, AES_BLOCK_SIZE);
		input[AES_BLOCK_SIZE] = input[AES_BLOCK_SIZE - 2];
		input[AES_BLOCK_SIZE + 1] = input[AES_BLOCK_SIZE - 1];

		unsigned char * outp = output + hashcrypt(&sha_ctx, &aes_ctx, input, AES_BLOCK_SIZE + 2, output);

		//  Add the header for the Literal Data Packet
		outp += hashcrypt(&sha_ctx, &aes_ctx, data_pkt_hdr, data_pkt_hdr_len, outp);
		fwrite(output, 1, outp - output, outfile);

		int total_read = encrypt_input_file(infile, outfile, &sha_ctx, &aes_ctx);
		assert((off_t) total_read == statstr.st_size);

		retval = write_gpg_mdc_packet(outfile, &sha_ctx, &aes_ctx);

		EVP_CIPHER_CTX_cleanup(&aes_ctx);
	}
	return retval;
}

/**
 *  Read public and secret key pair for login.
 *
 *  Retrieve the public and secret curve25519 encryption key pair for the specified user.
 *  Need to retrieve the public key first. If that is successful, use it to find and open the secret
 *  key file, then retrieve the secret key from that file.
 *
 *  @param login Name of the user for whom to find the key
 *  @param pub_key Output - public part of curve25519 key. Should point to crypto_box_PUBLICKEYBYTES bytes
 *  @param pub_key_len Output - num bytes in pub_key
 *  @param sec_key Output - secret part of curve25519 key. Should point to crypto_box_SECRETKEYBYTES bytes
 *  @param sec_key_len Output - num bytes in sec_key
 *  @param fp Output - fingerprint of Curve25519 key. Should point to at least GPG_KEY_FP_LEN bytes
 *  @param signer_fp Output - fingerprint of parent RSA key. Should point to at least GPG_KEY_FP_LEN bytes
 *  @return int 0 if successful, negative number if error
 */
static int
get_encryption_key(const char * login, unsigned char * pub_key, size_t * pub_key_len,
				   unsigned char * sec_key, size_t * sec_key_len, unsigned char * fp,
				   unsigned char * signer_fp)
{
	int retval = -1;

	if (get_public_encryption_key(login, pub_key, pub_key_len, fp, signer_fp) == 0) {
		const char * ssh_dir = get_user_ssh_dir(login);
		char * seckey_dir = check_seckey_dir(ssh_dir);
		if (seckey_dir != NULL) {
			struct sshkey * ssh_key;
			char * comment;

			if (retrieve_ssh_key(ssh_dir, &ssh_key, &comment) == 0) {
				FILE * infile = open_curve25519_seckey_file(seckey_dir, "r", pub_key, *pub_key_len);
				if (infile != NULL) {
					unsigned char buf[4096];

					int num_read = fread(buf, 1, sizeof(buf), infile);
					*sec_key_len = get_gpg_curve25519_seckey(buf, num_read, ssh_key, sec_key);
					if (*sec_key_len > 0) {
						retval = 0;
					}
					fclose(infile);
				}
			}

			free(seckey_dir);
		}
	}

	return retval;
}

/**
 *  Read login's ~/.pubkey file.
 *
 *  Retrieve the IronCore public key entries from the specified login's .pubkey file.
 *
 *  @param login User whose key info to retrieve
 *  @param rsa_key Output - public portion of RSA key from .pubkey. Should point to at least 512 bytes
 *  @param rsa_key_len Output - num bytes in rsa_key
 *  @param cv25519_key Output - public portion of Curve25519 key - at least crypto_box_SECRETKEYBYTES bytes
 *  @param cv25519_key_len Output - num bytes in cv25519_key
 *  @param rsa_fp Output - fingerprint of RSA key. Point to at least GPG_KEY_FP_LEN bytes
 *  @param cv25519_fp Output - fingerprint of Curve25519 key. Point to at least GPG_KEY_FP_LEN bytes
 *  @param uid Output - the "user ID" string associated with the keys. Should point to at least GPG_MAX_UID_LEN bytes
 *  @return int 0 if successful, negative number if error
 */
static int
read_pubkey_file(const char * login, unsigned char * rsa_key, size_t * rsa_key_len, unsigned char * cv25519_key,
				 size_t * cv25519_key_len, unsigned char * rsa_fp, unsigned char * cv25519_fp, char * uid)
{
	int retval = -1;
	struct passwd * pw = getpwnam(login);
	if (pw != NULL) {
		char fname[PATH_MAX + 1];
		snprintf(fname, PATH_MAX, "%s/.pubkey", pw->pw_dir);
		fname[PATH_MAX] = '\0';

		FILE * infile = fopen(fname, "r");
		if (infile != NULL) {
			char line[3000];
			while (fgets(line, sizeof(line), infile)) {
				char * lptr = line;
				char * token;
				size_t len;
				if (strncmp(line, "iron-rsa:", 9) == 0) {
					token = strsep(&lptr, " ");		// Skip initial "iron-rsa: "
					token = strsep(&lptr, " ");
					if (rsa_key != NULL) {
						*rsa_key_len = str2hex(token, rsa_fp);
					}
					token = strsep(&lptr, " ");
					if (rsa_fp != NULL) {
						len = str2hex(token, rsa_fp);
					}
					if (uid != NULL) {
						token = strsep(&lptr, " ");
						strncpy(uid, token, GPG_MAX_UID_LEN);
						uid[GPG_MAX_UID_LEN] = '\0';
					}
					retval = 0;
				} else if (strncmp(line, "iron-cv25519:", 13) == 0) {
					token = strsep(&lptr, " ");		// Skip initial "iron-cv25519: "
					token = strsep(&lptr, " ");
					if (cv25519_key != NULL) {
						*cv25519_key_len = str2hex(token, cv25519_key);
					}
					token = strsep(&lptr, " ");
					if (rsa_fp != NULL) {
						len = str2hex(token, cv25519_fp);
					}
					//  Ignore the uid on the subkey line
					retval = 0;
				}
			}
		}
	}

	return retval;
}


//================================================================================
//  GPG trustdb file funcs
//================================================================================


/**
 *  Write hash table to trustDB file.
 *
 *  Write the hash table. All but one of the records will be empty - this is just a block
 *  of zeroes with the record type at the start. Need to figure out the record and entry in
 *  that record that are non-zero. The "hash" of the key is just its first byte - figure out
 *  which entry in which record represents that byte, and fix that record accordingly.
 *
 *  @param tdb_file File to which to write table
 *  @param key Byte array containing the public key to add to table
 *  @param key_len Num bytes in key
 *  @return int ID of last record written to hash table, negative number if error
 */
static int
write_trustdb_htbl(FILE * tdb_file, const unsigned char * key, int key_len)
{
	unsigned char tdb_rec[GPG_TRUST_REC_SIZE];
	int key_hash = key[0];
	int retval = -1;

	int num_recs = (GPG_TRUST_MIN_HTBL_SIZE + GPG_TRUST_HTBL_ITEMS_PER_REC - 1) /
				   GPG_TRUST_HTBL_ITEMS_PER_REC;

	bzero(tdb_rec, sizeof(tdb_rec));
	tdb_rec[0] = GPG_TRUST_RECTYPE_HTBL;
	int rec_num = key_hash / GPG_TRUST_HTBL_ITEMS_PER_REC;
	int item_num = key_hash % GPG_TRUST_HTBL_ITEMS_PER_REC;

	//  Write the initial block of empty records
	int ct;
	int len = sizeof(tdb_rec);
	for (ct = 0; ct < rec_num && len == sizeof(tdb_rec); ct++) {
		len = fwrite(tdb_rec, 1, sizeof(tdb_rec), tdb_file);
	}

	if (len == sizeof(tdb_rec)) {
		//  Generate the non-empty record. The entry will contain a four-byte integer that is the
		//  number of the first record past the hash table. This number will always be less than
		//  256, so we will just set the one byte at the end of the int to the value.
		int byte_idx = 2 + item_num * 4 + 3;
		tdb_rec[byte_idx] = num_recs + 1;
		if (fwrite(tdb_rec, 1, sizeof(tdb_rec), tdb_file) == sizeof(tdb_rec)) {
			tdb_rec[byte_idx] = 0x00;		// Restore "empty" record
			ct++;

			//  Write the remaining empty records
			while (ct < num_recs && len == sizeof(tdb_rec)) {
				len = fwrite(tdb_rec, 1, sizeof(tdb_rec), tdb_file);
				ct++;
			}

			if (len == sizeof(tdb_rec)) {
				retval = num_recs;
			}
		}
	}

	return retval;
}

/**
 *  Generate the "version" packet for trustDB file.
 *
 *  @param rec Place to write generated packet (at least 40 bytes)
 */
static void
generate_gpg_trustdb_version(unsigned char * rec)
{
	unsigned char * recp = rec;

	bzero(rec, GPG_TRUST_REC_SIZE);
	*recp = GPG_TRUST_RECTYPE_VER;     recp++;
	strcpy(recp, "gpg");               recp += 3;
	*recp = GPG_TRUSTDB_VER;           recp++;
	*recp = GPG_TRUST_DFLT_MARGINALS;  recp++;
	*recp = GPG_TRUST_DFLT_COMPLETES;  recp++;
	*recp = GPG_TRUST_DFLT_CERT_DEPTH; recp++;
	*recp = GPG_TRUST_MODEL_PGP;       recp++;
	*recp = GPG_TRUST_DFLT_MIN_CERT;   recp++;
	/*  Skip reserved  */  			   recp += 2;
	long tmp = htonl(gpg_now);
	memcpy(recp, &tmp, sizeof(tmp));   recp += 4;
	/*  Leave next check 0  */ 		   recp += 4; 
	/*  Skip reserved  */              recp += 8;
	/*  Leave first free 0  */         recp += 4;
	/*  Skip reserved  */              recp += 4;
	tmp = htonl(1L);	/*  Rec # of start of hash table is 1  */
	memcpy(recp, &tmp, sizeof(tmp));
}

/**
 *  Generate the "trust" packet for trustDB file.
 *
 *  @param rec Place to write generated packet (at least key_len + 10 bytes)
 *	@param key Byte array with public key being added to DB
 *	@param key_len Num bytes in key
 *	@param next_rec index of the record following hash table where trust packet will go
 */
static void
generate_gpg_trustdb_trust(unsigned char * rec, const unsigned char * key, int key_len, int next_rec)
{
	unsigned char * recp = rec;

	bzero(rec, GPG_TRUST_REC_SIZE);
	*recp = GPG_TRUST_RECTYPE_TRUST;   recp++;
	/*  Skip reserved  */  			   recp++;
	memcpy(recp, key, key_len);		   recp += key_len;
	*recp = GPG_TRUST_ULTIMATE;        recp++;
	/*  Leave depth 0 */  			   recp++;
	/*  Leave min owner trust 0 */     recp++;
	/*  Skip reserved  */  			   recp++;
	long tmp = htonl(next_rec);
	memcpy(recp, &tmp, sizeof(tmp));
}

/**
 *  Generate the "valid" packet for trustDB file.
 *
 *  @param rec Place to write generated packet (at least 28 bytes)
 *	@param uid String identifying user (typically "Name <emailaddr>")
 */
static void
generate_gpg_trustdb_valid(unsigned char * rec, const char * uid)
{
	unsigned char * recp = rec;

	bzero(rec, GPG_TRUST_REC_SIZE);
	*recp = GPG_TRUST_RECTYPE_VALID;   recp++;
	/*  Skip reserved  */  			   recp++;
	
	/* Compute the RIPE-MD160 hash of the UID. Yes, RIPE-MD160. Thanks, GPG. */
	unsigned char hash[RIPEMD160_DIGEST_LENGTH];
	RIPEMD160_CTX ctx;
	RIPEMD160_Init(&ctx);
	RIPEMD160_Update(&ctx, uid, strlen(uid));
	RIPEMD160_Final(hash, &ctx);

	memcpy(recp, hash, sizeof(hash));  recp += sizeof(hash);
	*recp = GPG_TRUST_ULTIMATE;        recp++;	//  Validity
	/*  Leave next rec 0 */			   recp += 4;
	/*  Leave full count 0 */          recp++;
	/*  Leave marginal count 0 */
}

/**
 *  Generate contents of trustDB and write file.
 *
 *  Create the trustdb.gpg file and write it under the specified .ssh directory.
 *
 *  @param ssh_dir Path to the user's .ssh directory (usually under ~<login>)
 *  @param key Public key to add trust
 *  @param key_len Num bytes in key
 *	@param uid String identifying user (typically "Name <emailaddr>")
 *  @return int 0 if successful, negative number if error
 */
static int
write_trustdb_file(const char * ssh_dir, const unsigned char * key, size_t key_len, const char * uid)
{
	int retval = -1;

	char file_name[PATH_MAX + 1];
	snprintf(file_name, PATH_MAX, "%s%s", ssh_dir, GPG_TRUSTDB_FNAME);
	file_name[PATH_MAX] = '\0';
	FILE * tdb_fp = fopen(file_name, "w");
	if (tdb_fp != NULL) {
		fchmod(fileno(tdb_fp), S_IRUSR | S_IWUSR);

		unsigned char tdb_rec[GPG_TRUST_REC_SIZE];

		generate_gpg_trustdb_version(tdb_rec);
		if (fwrite(tdb_rec, 1, sizeof(tdb_rec), tdb_fp) == sizeof(tdb_rec)) {
			int last_rec = write_trustdb_htbl(tdb_fp, key, key_len);
			if (last_rec > 0) {
				//  Now write the trust and valid records. The trust record will be # last_rec + 1, so
				//  the valid record will be # last_rec + 2.
				generate_gpg_trustdb_trust(tdb_rec, key, key_len, last_rec + 2);
				if (fwrite(tdb_rec, 1, sizeof(tdb_rec), tdb_fp) == sizeof(tdb_rec)) {
					generate_gpg_trustdb_valid(tdb_rec, uid);
					if (fwrite(tdb_rec, 1, sizeof(tdb_rec), tdb_fp) == sizeof(tdb_rec)) {
						retval = 0;
					}
				}
			}
		}

		fclose(tdb_fp);
	}

	return retval;
}


//================================================================================
//  Publicly visible funcs
//================================================================================

/**
 *  Confirm that public and private key files are in place for specified login.
 *
 *  Check to see if the public/private key files containing the specified login's rsa & curve25519 keys
 *  exist and are accessible. If not, and if we have access to the login's .ssh directory, try to create
 *  new files.
 *
 *  @param login Login of the target user (usually the user running the executable)
 *  @return int zero if keys in place, -1 if error
 */
int
check_iron_keys(const char * const login)
{
	int retval = -1;

	const char * ssh_dir = get_user_ssh_dir(login);
	if (ssh_dir != NULL && *ssh_dir) {
		char file_name[PATH_MAX + 1];
		snprintf(file_name, PATH_MAX, "%s%s", ssh_dir, GPG_PUBLIC_KEY_FNAME);
		file_name[PATH_MAX] = '\0';

		struct stat fstats;

		if (stat(file_name, &fstats) >= 0) {
			char * seckey_dir = check_seckey_dir(ssh_dir);
			if (seckey_dir != NULL) {
				//  If the directory is there, assume that the key files are in place.
				retval = 0;
				free(seckey_dir);
			}
		}

		if (retval < 0) {
			if (errno == EACCES) {
				logit("No access to the %s directory.", ssh_dir);
			}
			else if (errno == ENOENT) {
				//  Try to generate key pair and create files.
				retval = generate_iron_keys(ssh_dir, login);
			}
			else {
				logit("Error checking %s - %s", file_name, strerror(errno));
			}
		}

	}

	return retval;
}

/**
 *  Retrieve public encryption key for specified login.
 *
 *  Attempt to read the public encryption key from the specified login's ~/.pubkey file. If that is not
 *  available, read the public encryption subkey for the login from the ~<login>/.ssh/pubkey.gpg file.
 *
 *  @param login Name of the user for whom to find the key
 *  @param key Output - public portion of Curve25519 key. Should point to at least crypto_box_PUBLICKEYBYTES bytes
 *  @param key_len Output - num bytes in key
 *  @param fp Output - fingerprint of Curve25519 key. Should point to at least GPG_KEY_FP_LEN bytes
 *  @param signer_fp Output - fingerprint of RSA key. Should point to at least GPG_KEY_FP_LEN bytes
 *  @return int 0 if successful, negative number if error
 */
int
get_public_encryption_key(const char * login, unsigned char * key, size_t * key_len,
						  unsigned char * fp, unsigned char * signer_fp)
{
	int retval = read_pubkey_file(login, NULL, NULL, key, key_len, signer_fp, fp, NULL);

	if (retval != 0) {
		char key_file_name[PATH_MAX + 1];
		FILE * key_file;

		const char * ssh_dir = get_user_ssh_dir(login);
		snprintf(key_file_name, PATH_MAX, "%s%s", ssh_dir, GPG_PUBLIC_KEY_FNAME);
		key_file_name[PATH_MAX] = '\0';
		key_file = fopen(key_file_name, "r");
		if (key_file != NULL) {
			gpg_message * pubkey_pkt = get_pub_key_packet(key_file);
			if (pubkey_pkt != NULL) {
				compute_gpg_key_fingerprint(pubkey_pkt, signer_fp);

				gpg_message * subkey_pkt = get_curve25519_key_packet(key_file);
				if (subkey_pkt != NULL) {
					const unsigned char * key_ptr = sshbuf_ptr(subkey_pkt->data) + sizeof(curve25519_oid) + 6;
					*key_len = (*key_ptr << 8) + *(key_ptr + 1);
					//  Size in bits from the header of the MPI - convert to bytes, then deduct leading 0x40
					*key_len = (*key_len + 7) / 8;
					(*key_len)--;
					key_ptr += 2;
					assert(*(key_ptr++) == GPG_ECC_PUBKEY_PREFIX);
					memcpy(key, key_ptr, *key_len);
					compute_gpg_key_fingerprint(subkey_pkt, fp);

					sshbuf_free(subkey_pkt->data);
					free(subkey_pkt);
					retval = 0;
				}
				sshbuf_free(pubkey_pkt->data);
				free(pubkey_pkt);
			}

			fclose(key_file);
		}
	}

	return retval;
}

/**
 *  Encrypt the specified file and write to new file.
 *
 *  Given the name of an input file, form an output file name by appending .iron, then generate the GPG
 *  packets necessary to share the encrypted data with specified recipients. Follow that with a packet
 *  containing the encrypted data.
 *
 *  @param fname Path of the file to encrypt
 *  @param enc_fname Output the path of the encrypted file - should point to at least PATH_MAX + 1 chars
 *  @return int - file number of the output file, or < 0 if error
 */
int
write_gpg_encrypted_file(const char * fname, int write_tmpfile, char * enc_fname)
{
	int retval = -1;

	FILE * infile = fopen(fname, "r");
	if (infile != NULL) {
		FILE * outfile;
		if (write_tmpfile) {
			outfile = tmpfile();
		} else {
			outfile = open_encrypted_output_file(fname, enc_fname);
		}

		if (outfile != NULL) {
			unsigned char sym_key_frame[AES256_KEY_BYTES + AES_WRAP_BLOCK_SIZE];
			int frame_len = generate_gpg_sym_key_frame(sym_key_frame);
			assert(frame_len == sizeof(sym_key_frame));
			retval = 0;
			// Need to generate a "Public Key Encrypted Session Key Packet" for each of the recipients.
			const gpg_public_key * recipient_key;
			int recip_ct = get_recipients(&recipient_key);
			for (int i = 0; retval == 0 && i < recip_ct; i++) {
				gpg_message pkesk;
				generate_gpg_pkesk_packet(recipient_key + i, sym_key_frame, sizeof(sym_key_frame), &pkesk);
				retval = put_gpg_message(outfile, &pkesk);
				sshbuf_free(pkesk.data);
				pkesk.data = NULL;
			}

			if (retval == 0) {
				retval = write_encrypted_data_file(infile, fname, outfile, sym_key_frame + 1);
				if (retval == 0) {
					retval = fileno(outfile);
				}
			}
			fflush(outfile);
			rewind(outfile);
		}
		fclose(infile);
	}

	return retval;
}

/**
 *  Read GPG encrypted data file, write decrypted data to other file.
 *
 *  Process a file that should contain GPG-encrypted data. This data is expected to be one or more Public Key
 *  Encrypted Symmetric Key (PKESK) packets, one of which was generated for the current recipient, followed by
 *  a Symmetrically Encrypted and Integrity Protected Data (SEIPD) packet. This packet must be decrypted to
 *  recover a Literal Data packet, followed by a Modification Detection Code (MDC) packet.
 *
 *  If we can find the PKESK packet and successfully recover the symmetric key from it, we find the SEIPD packet,
 *  open an output file (by removing the ".iron" suffix from the input file name, or by appending ".iron.dec"
 *  if the input file doesn't end in ".iron", decrypt the data, find the Literal Data packet, retrieve the file
 *  data from it, and write it to the output file. After the Literal Data packet, validate that the contents of
 *  the MDC packet matches the running hash we have computed.
 *
 *  @param fname Name of the input file to read
 *  @param sec_key Pointer to secret key of recipient. Should be crypto_box_SECRETKEYBYTES long.
 *  @param pub_key Pointer to gpg_public_key struct containing public key of recipient and fingerprint.
 *  @return 0 if successful, -1 if errors
 */
int
write_gpg_decrypted_file(const char * login, const char * fname, char * dec_fname)
{
	unsigned char	pub_key[crypto_box_PUBLICKEYBYTES];
	unsigned char	sec_key[crypto_box_SECRETKEYBYTES];
	size_t			pk_len;
	size_t			sk_len;
	unsigned char	key_fp[GPG_KEY_FP_LEN];
	unsigned char	signing_key_fp[GPG_KEY_FP_LEN];

	int retval = get_encryption_key(login, pub_key, &pk_len, sec_key, &sk_len, key_fp, signing_key_fp);
	if (retval < 0) {
		return retval;
	}
	retval = -1;

	FILE * infile = fopen(fname, "r");
	if (infile != NULL) {
		unsigned char msg[512];
		gpg_tag next_tag;
		int     next_len;

		if (get_gpg_pkesk_packet(infile, key_fp + GPG_KEY_ID_OFFSET, msg, &next_tag, &next_len) == 0) {
			unsigned char * msg_ptr = msg;
			if (*(msg_ptr++) == GPG_PKALGO_ECDH) {
				const unsigned char *ephem_pk;
				msg_ptr += extract_ephemeral_key(msg_ptr, &ephem_pk);

				unsigned char secret[crypto_box_BEFORENMBYTES];
				generate_curve25519_shared_secret(sec_key, ephem_pk, secret);

				unsigned char sym_key[AES256_KEY_BYTES];
				extract_sym_key(msg_ptr, secret, key_fp, sym_key);

				//  The next header we read after we processed all the PKESK packets should be the SEIPD
				//  packet. After the header, there is a one byte version number, then encrypted data.
				//
				//  Note that the encrypted data will always be long enough to output at least two blocks (32
				//  bytes) in the first call to DecryptUpdate - the header + MDC packet is more than 32 bytes,
				//  even if the file name is 1 character long and the file is empty.
				assert(next_tag == GPG_TAG_SEIP_DATA);
				unsigned char output[CHUNK_SIZE + 2 * AES_BLOCK_SIZE];

				unsigned char seipd_ver = fgetc(infile);
				assert(seipd_ver == GPG_SEIPD_VERSION);

				SHA_CTX sha_ctx;
				SHA1_Init(&sha_ctx);

				EVP_CIPHER_CTX aes_ctx;
				const EVP_CIPHER * aes_cipher = EVP_aes_256_cfb();
				EVP_CIPHER_CTX_init(&aes_ctx);
				if (EVP_DecryptInit_ex(&aes_ctx, aes_cipher, NULL /*dflt engine*/, sym_key,
							NULL /*dflt iv*/)) {
					int num_dec;
					ssize_t len;
					int extra;
					char local_fname[PATH_MAX + 1];
					unsigned char * optr = output + 
						process_enc_data_hdr(&sha_ctx, &aes_ctx, infile, output, local_fname, &num_dec, &len, &extra);

					char dec_fname[PATH_MAX + 1];
					FILE * outfile = open_decrypted_output_file(local_fname, fname, dec_fname);
					if (outfile != NULL) {
						//  Flush remainder of output buffer that is file data. May still be some left that is
						//  all or part of the MDC file. 
						fwrite(optr, 1, num_dec, outfile);
						SHA1_Update(&sha_ctx, optr, num_dec);
						len -= num_dec;

						retval = process_enc_data(&sha_ctx, &aes_ctx, infile, outfile, output, optr - output,
								len, extra);

						if (retval == 0) {
							fflush(outfile);
							rewind(outfile);
							retval = fileno(outfile);
						}
					}
				}
			}
		}
		fclose(infile);
	}

	return retval;
}


//================================================================================
//  Functions to manipulate list of registered recipients - the users with which
//  an uploaded file will be shared.
//================================================================================
#define RECIPIENT_LIST_BLOCK_LEN	5
static gpg_public_key * recipient_list = 0;
static int max_recipients = 0;
static int num_recipients = 0;

/**
 *  Return current registered recipient list.
 *
 *  Return a pointer to the current list of registered recipients. If the list is empty, create it and
 *  put the current user into the list.
 *
 *  @param recip_list Place to write the pointer to the recipient list.
 *  @return int Num recipients in list, or negative number if error (unable to initialize list)
 */
static int
get_recipients(const gpg_public_key ** recip_list)
{
	if (recipient_list == NULL) {
		recipient_list = calloc(RECIPIENT_LIST_BLOCK_LEN, sizeof(gpg_public_key));
		max_recipients = RECIPIENT_LIST_BLOCK_LEN;
		num_recipients = 0;

		//  The current user is always included in the recipient list, so get that entry added.
		if (add_recipient(user_login) != 0) {
			*recip_list = NULL;
			return -1;
		}
	}

	*recip_list = recipient_list;
	return num_recipients;
}

/**
 *  Add a recipient to registered list.
 *
 *  Add an entry for the specified user to the list of registered recipients. Requires that the user
 *  has a ~<login>/.pubkey file.
 *
 *  @param login User to add
 *  @return int 0 if successful, negative number if error
 */
int
add_recipient(const char * login)
{
	int retval = 0;
	for (int i = 0; i < num_recipients; i++) {
		if (strcmp(recipient_list[i].login, login) == 0) {
			logit("User %s already in the recipient list.", login);
			retval = -1;
			break;
		}
	}

	if (retval == 0) {
		if (num_recipients == max_recipients) {
			//  List full - need to expand. Just add block of RECIPIENT_LIST_BLOCK_LEN entries each time.
			max_recipients += RECIPIENT_LIST_BLOCK_LEN;
			recipient_list = xreallocarray(recipient_list, max_recipients, sizeof(gpg_public_key));
		}

		gpg_public_key * new_ent = recipient_list + num_recipients;
		strncpy(new_ent->login, login, MAX_LOGIN_LEN);
		new_ent->login[MAX_LOGIN_LEN] = 0;
		size_t key_len;
		if (get_public_encryption_key(login, new_ent->key, &key_len, new_ent->fp, new_ent->signer_fp) == 0) {
			num_recipients++;
		} else {
			logit("Unable to retrieve public key information for user %s", login);
			retval = -1;
		}
	}

	return retval;
}

/**
 *  Remove a recipient from registered list.
 *
 *  Remove the entry for the specified user from the list of registered recipients.
 *
 *  @param login User to remove
 *  @return int 0 if successful, negative number if error
 */
int
remove_recipient(const char * login)
{
	int retval = -1;

	if (strcmp(login, user_login) == 0) {
		logit("Current user (%s) cannot be removed from the recipient list. Ignored.", login);
	} else {
		int i;
		for (i = 0; i < num_recipients; i++) {
			if (strcmp(recipient_list[i].login, login) == 0) {
				retval = 0;
				break;
			}
		}

		if (retval == 0) {
			if (i != num_recipients - 1) {
				memmove(recipient_list + i, recipient_list + i + 1, num_recipients - i - 1);
			}
			num_recipients--;
		} else {
			logit("User %s not found in the recipient list.", login);
		}
	}

	return retval;
}

/**
 *  Reset the registered list.
 *
 *  Empty out the list of registered recipients. The next time it is accessed, it should be repopulated
 *  with the current user's entry.
 */
void
reset_recipients()
{
	free(recipient_list);
	recipient_list = NULL;
	num_recipients = 0;
	max_recipients = 0;
}


/* ================================================================================================================
 * Poor programmer's unit test harness. If you compile this file with TESTING defined, it will generate a main().
 * Link it and run it to execute unit tests. Right now, they are validated with asserts, so the first failure will
 * stop the tests.
 * ================================================================================================================ */
#ifdef TESTING

#include "regress/unittests/test_helper/test_helper.h"

#include <string.h>
#include <unistd.h>
#include <pwd.h>


char * user_login = NULL;

/*  Retrieve next packet - read header, then read body specified by header length.  */
static int
get_gpg_message(FILE * infile, gpg_message * msg)
{
	int retval = -1;

	if (get_tag_and_size(infile, &msg->tag, &msg->len) == 0) {
		if (msg->len > 0) {
			unsigned char * buf = malloc(msg->len);
			int num_read = fread(buf, sizeof(unsigned char), msg->len, infile);
			if (num_read == msg->len) {
				msg->data = sshbuf_from(buf, msg->len);
				retval = 0;
			}
		}
	}

	return retval;
}

/*  Read a multi-precision integer of the format used in GPG (two bytes containing the
 *  length in bits, MSB-first, followed by the bits, MSB first, padded with leading zero bits
 *  to full octets) and convert it into an OpenSSL BIGNUM.
 */
static int
get_bignum(struct sshbuf * buf, BIGNUM * bignum)
{
	int retval = -1;

	u_int16_t len;

	u_char tmp[1024];
   	sshbuf_get_u16(buf, &len);
	int num_bytes = (len + 7) / 8;

	if (sshbuf_get(buf, tmp, num_bytes) == 0) {
		BN_bin2bn(tmp, num_bytes, bignum);
		retval = 0;
	}

	return retval;
}


typedef struct tdata {
	unsigned char * h;
	size_t h_len;
	gpg_tag tag;
	ssize_t size;
} tdata;

static void
do_tag_and_size(const tdata * td)
{
	unsigned char hdr[8];
	int retval;
	gpg_tag tag;
	ssize_t size;

	retval = extract_tag_and_size(td->h, &tag, &size);
	ASSERT_INT_EQ(retval, td->h_len);
	ASSERT_INT_EQ(tag, td->tag);
	ASSERT_INT_EQ(size, td->size);

	retval = generate_tag_and_size(tag, size, hdr);
	ASSERT_INT_EQ(retval, td->h_len);
	ASSERT_INT_EQ(memcmp(hdr, td->h, retval), 0);
}

static void
do_read_tag_and_size(FILE * infile, const tdata * td)
{
	int retval;
	gpg_tag tag;
	ssize_t size;

	retval = get_tag_and_size(infile, &tag, &size);
	ASSERT_INT_EQ(retval, 0);
	ASSERT_INT_EQ(tag, td->tag);
	ASSERT_INT_EQ(size, td->size);
}

static void
test_tags()
{
	TEST_START("tag_and_len");

	unsigned char h0[] = {0x84, 0x00};
	unsigned char h1[] = {0x88, 0x01};
	unsigned char h2[] = {0x8d, 0x12, 0x34};
	unsigned char h3[] = {0x92, 0xfe, 0xdc, 0xba, 0x98};
	unsigned char h4[] = {0x97};
	unsigned char h5[] = {0xd1, 0x23};
	unsigned char h6[] = {0xd2, 0xc1, 0x23};
	unsigned char h7[] = {0xd3, 0xff, 0x12, 0x34, 0x56, 0x78};
	unsigned char h8[] = {0xfc, 0xe1};
		
	tdata test_item[] = {
		{ h0, sizeof(h0), GPG_TAG_PKESK, 0 },
		{ h1, sizeof(h1), GPG_TAG_SIGNATURE, 1 },
		{ h2, sizeof(h2), GPG_TAG_SKESK, 0x1234 },
		{ h3, sizeof(h3), GPG_TAG_ONE_PASS_SIGNATURE, 0xfedcba98 },
		{ h4, sizeof(h4), GPG_TAG_SECRET_KEY, -1 },
		{ h5, sizeof(h5), GPG_TAG_USER_ATTRIBUTE, 0x23 },
		{ h6, sizeof(h6), GPG_TAG_SEIP_DATA, 0x1e3 },
		{ h7, sizeof(h7), GPG_TAG_MOD_DETECT_CODE, 0x12345678 },
		{ h8, sizeof(h8), GPG_TAG_RESERVED1, 2 },
	};

	for (size_t i = 0; i < (sizeof(test_item) / sizeof(tdata) - 1); i++) {
		//  Need to test the "partial length" extract separately, because we don't generate those headers yet
		do_tag_and_size(test_item + i);
	}
	int retval;
	gpg_tag tag;
	ssize_t size;

	retval = extract_tag_and_size(h8, &tag, &size);
	ASSERT_INT_EQ(retval, sizeof(h8));
	ASSERT_INT_EQ(tag, GPG_TAG_RESERVED1);
	ASSERT_INT_EQ(size, 2);

	//  Now try writing a file and testing the functions that read tag and size from the file.
	FILE * tstfile = tmpfile();
	for (size_t i = 0; i < (sizeof(test_item) / sizeof(tdata)); i++) {
		fwrite(test_item[i].h, 1, test_item[i].h_len, tstfile);
	}
	rewind(tstfile);
	
	for (size_t i = 0; i < (sizeof(test_item) / sizeof(tdata)); i++) {
		do_read_tag_and_size(tstfile, test_item + i);
	}

	retval = get_tag_and_size(tstfile, &tag, &size);	//  Should be at EOF now
	ASSERT_INT_EQ(retval, -1);
}

static void
do_put_msg(FILE * tstfile, tdata * test_item)
{
	gpg_message msg;
	msg.tag = test_item->tag;
	msg.len = test_item->size;
	msg.data = sshbuf_from(test_item->h, test_item->h_len);
	int retval = put_gpg_message(tstfile, &msg);
	ASSERT_INT_EQ(retval, 0);
}

static void
do_get_msg(FILE * tstfile, tdata * test_item)
{
	gpg_message msg;
	int retval = get_gpg_message(tstfile, &msg);
	ASSERT_INT_EQ(retval, 0);
	ASSERT_INT_EQ(msg.tag, test_item->tag);
	ASSERT_INT_EQ(msg.len, test_item->size);
	ASSERT_INT_EQ(msg.len, test_item->size);
	ASSERT_INT_EQ(memcmp(sshbuf_ptr(msg.data), test_item->h, test_item->h_len), 0);
	sshbuf_free(msg.data);
}

static void
test_msgs(void)
{
	//  Some faux GPG messages
	unsigned char buf[] = {
		0x84, 0x04, 0x01, 0x23, 0x45, 0x67,
		0xd1, 0x04, 0x01, 0x23, 0x45, 0x67
	};

	unsigned char h0[] = {0x01, 0x23, 0x45, 0x67};
	unsigned char * h1 = malloc(256);
	for (int i = 0; i < 256; i++) {
		h1[i] = i;
	}
	unsigned char * h2 = malloc(4096);
	for (int i = 0; i < 4096; i++) {
		h2[i] = i;
	}
		
	tdata test_item[] = {
		{ h0, sizeof(h0), GPG_TAG_PKESK, sizeof(h0) },			// Hand written from buf
		{ h0, sizeof(h0), GPG_TAG_USER_ATTRIBUTE, sizeof(h0) }, // Hand written from buf
		{ h0, sizeof(h0), GPG_TAG_PKESK, sizeof(h0) },
		{ h1, 256, GPG_TAG_PKESK, 256 },
		{ h2, 4096, GPG_TAG_PKESK, 4096 },
		{ h0, sizeof(h0), GPG_TAG_USER_ATTRIBUTE, sizeof(h0) },
		{ h1, 256, GPG_TAG_USER_ATTRIBUTE, 256 },
		{ h2, 4096, GPG_TAG_USER_ATTRIBUTE, 4096 }
	};

	FILE * tstfile = tmpfile();
	fwrite(buf, 1, sizeof(buf), tstfile);
	for (size_t i = 2; i < sizeof(test_item) / sizeof(tdata); i++) {
		do_put_msg(tstfile, test_item + i);
	}
	rewind(tstfile);

	for (size_t i = 0; i < sizeof(test_item) / sizeof(tdata); i++) {
		do_get_msg(tstfile, test_item + i);
	}

	fclose(tstfile);

	gpg_message msg;
	int retval = get_gpg_message(tstfile, &msg);
	ASSERT_INT_EQ(retval, -1);
	retval = put_gpg_message(tstfile, &msg);
	ASSERT_INT_EQ(retval, -1);
}

int
mainline(int argc, char **argv)
{
	unsigned char buf[] = {
		//  Next, some faux GPG messages
		0x84, 0x04, 0x01, 0x23, 0x45, 0x67,
		0xcc, 0x04, 0x12, 0x34, 0x56, 0x78,
		//  Next, some bignums, all packed into a GPG message
		0x84, 0x2d,
		0x00, 0x06, 0x23,
		0x00, 0x08, 0xa5,
		0x00, 0x18, 0x12, 0x34, 0x56,
		0x01, 0x00, 
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff
	};


	//  Create a file containing known content to read
	FILE * tstfile = tmpfile();
	fwrite(buf, sizeof(buf), sizeof(unsigned char), tstfile);
	rewind(tstfile);

	gpg_message msg;
	gpg_tag tag;
	ssize_t size;
	int retval;
   
	retval = get_gpg_message(tstfile, &msg);
	assert(retval == 0);
	assert(msg.tag == GPG_TAG_PKESK);
	assert(msg.len == 4);
	const unsigned char * tmp_ptr = sshbuf_ptr(msg.data);
	assert(tmp_ptr[0] == 0x01);
	assert(tmp_ptr[1] == 0x23);
	assert(tmp_ptr[2] == 0x45);
	assert(tmp_ptr[3] == 0x67);
	sshbuf_free(msg.data);
	msg.data = NULL;

	retval = get_gpg_message(tstfile, &msg);
	assert(retval == 0);
	assert(msg.tag == GPG_TAG_TRUST);
	assert(msg.len == 4);
	tmp_ptr = sshbuf_ptr(msg.data);
	assert(tmp_ptr[0] == 0x12);
	assert(tmp_ptr[1] == 0x34);
	assert(tmp_ptr[2] == 0x56);
	assert(tmp_ptr[3] == 0x78);
	sshbuf_free(msg.data);
	msg.data = NULL;

	retval = get_gpg_message(tstfile, &msg);
	assert(retval == 0);
	assert(msg.tag == GPG_TAG_PKESK);
	assert(msg.len == 45);

	BIGNUM * bn = BN_new();
	retval = get_bignum(msg.data, bn);
	assert(retval == 0);
	assert(BN_num_bits(bn) == 6);

	retval = get_bignum(msg.data, bn);
	assert(retval == 0);
	assert(BN_num_bits(bn) == 8);

	retval = get_bignum(msg.data, bn);
	assert(retval == 0);
	assert(BN_num_bits(bn) == 21);

	retval = get_bignum(msg.data, bn);
	assert(retval == 0);
	assert(BN_num_bits(bn) == 256);

	FILE * outfile = tmpfile();

	unsigned char tagbuf[6];
	int len = generate_tag_and_size(GPG_TAG_PKESK, -1, tagbuf);
	assert(len == 1);
	assert (tagbuf[0] == 0x87);
	fwrite(tagbuf, 1, len, outfile);

	len = generate_tag_and_size(GPG_TAG_PKESK, 1, tagbuf);
	assert(len == 2);
	assert (tagbuf[0] == 0x84 && tagbuf[1] == 0x01);
	fwrite(tagbuf, 1, len, outfile);

	len = generate_tag_and_size(GPG_TAG_MARKER, 0x101, tagbuf);
	assert(len == 3);
	assert (tagbuf[0] == 0xa9 && tagbuf[1] == 0x01 && tagbuf[2] == 0x01);
	fwrite(tagbuf, 1, len, outfile);

	len = generate_tag_and_size(GPG_TAG_PUBLIC_SUBKEY, 0x10000001, tagbuf);
	assert(len == 5);
	assert (tagbuf[0] == 0xba);
	assert (tagbuf[1] == 0x10);
	assert (tagbuf[2] == 0x00);
	assert (tagbuf[3] == 0x00);
	assert (tagbuf[4] == 0x01);
	fwrite(tagbuf, 1, len, outfile);

	len = generate_tag_and_size(GPG_TAG_USER_ATTRIBUTE, 1, tagbuf);
	assert(len == 2);
	assert (tagbuf[0] == 0xd1 && tagbuf[1] == 0x01);
	fwrite(tagbuf, 1, len, outfile);

	len = generate_tag_and_size(GPG_TAG_SEIP_DATA, 0xc0, tagbuf);
	assert(len == 3);
	assert (tagbuf[0] == 0xd2);
	assert (tagbuf[1] == 0xc0);
	assert (tagbuf[2] == 0x00);
	fwrite(tagbuf, 1, len, outfile);

	len = generate_tag_and_size(GPG_TAG_SEIP_DATA, 0x20bf, tagbuf);
	assert(len == 3);
	assert (tagbuf[0] == 0xd2);
	assert (tagbuf[1] == 0xdf);
	assert (tagbuf[2] == 0xff);
	fwrite(tagbuf, 1, len, outfile);

	len = generate_tag_and_size(GPG_TAG_SEIP_DATA, 0x3000, tagbuf);
	assert(len == 6);
	assert (tagbuf[0] == 0xd2);
	assert (tagbuf[1] == 0xff);
	assert (tagbuf[2] == 0x00);
	assert (tagbuf[3] == 0x00);
	assert (tagbuf[4] == 0x30);
	assert (tagbuf[5] == 0x00);
	fwrite(tagbuf, 1, len, outfile);

	len = generate_tag_and_size(GPG_TAG_RESERVED4, 0x12345678, tagbuf);
	assert(len == 6);
	assert (tagbuf[0] == 0xff);
	assert (tagbuf[1] == 0xff);
	assert (tagbuf[2] == 0x12);
	assert (tagbuf[3] == 0x34);
	assert (tagbuf[4] == 0x56);
	assert (tagbuf[5] == 0x78);
	fwrite(tagbuf, 1, len, outfile);

	/* Don't handle the partial packet lengths yet, so we can only do lengths through 32 bits */
	len = generate_tag_and_size(GPG_TAG_RESERVED4, 0x100000001, tagbuf);
	assert(len == -1);

	msg.tag = GPG_TAG_SECRET_SUBKEY;
	msg.len = 8;
	msg.data = sshbuf_from("Test1234", msg.len);
	retval = put_gpg_message(outfile, &msg);
	assert(retval == 0);
	sshbuf_free(msg.data);
	msg.data = NULL;

	msg.tag = GPG_TAG_USER_ATTRIBUTE;
	msg.data = sshbuf_new();
	retval = put_bignum(msg.data, bn);
	assert(retval == 0);
	msg.len = sshbuf_len(msg.data);
	retval = put_gpg_message(outfile, &msg);
	assert(retval == 0);
	sshbuf_free(msg.data);
	msg.data = NULL;
	BN_free(bn);

	rewind(outfile);

	retval = get_tag_and_size(outfile, &tag, &size);
	assert(retval == 0);
	assert(tag == GPG_TAG_PKESK);
	assert(size == -1);

	retval = get_tag_and_size(outfile, &tag, &size);
	assert(retval == 0);
	assert(tag == GPG_TAG_PKESK);
	assert(size == 1);

	retval = get_tag_and_size(outfile, &tag, &size);
	assert(retval == 0);
	assert(tag == GPG_TAG_MARKER);
	assert(size == 0x101);

	retval = get_tag_and_size(outfile, &tag, &size);
	assert(retval == 0);
	assert(tag == GPG_TAG_PUBLIC_SUBKEY);
	assert(size == 0x10000001);

	retval = get_tag_and_size(outfile, &tag, &size);
	assert(retval == 0);
	assert(tag == GPG_TAG_USER_ATTRIBUTE);
	assert(size == 1);

	retval = get_tag_and_size(outfile, &tag, &size);
	assert(retval == 0);
	assert(tag == GPG_TAG_SEIP_DATA);
	assert(size == 0xc0);

	retval = get_tag_and_size(outfile, &tag, &size);
	assert(retval == 0);
	assert(tag == GPG_TAG_SEIP_DATA);
	assert(size == 0x20bf);

	retval = get_tag_and_size(outfile, &tag, &size);
	assert(retval == 0);
	assert(tag == GPG_TAG_SEIP_DATA);
	assert(size == 0x3000);

	retval = get_tag_and_size(outfile, &tag, &size);
	assert(retval == 0);
	assert(tag == GPG_TAG_RESERVED4);
	assert(size == 0x12345678);

	retval = get_gpg_message(outfile, &msg);
	assert(retval == 0);
	assert(msg.tag == GPG_TAG_SECRET_SUBKEY);
	assert(msg.len == 8);
	assert(memcmp(sshbuf_ptr(msg.data), "Test1234", 8) == 0);

	retval = get_gpg_message(outfile, &msg);
	assert(retval == 0);
	assert(msg.tag == GPG_TAG_USER_ATTRIBUTE);
	assert(msg.len == 34);
	assert(memcmp(sshbuf_ptr(msg.data), buf + (sizeof(buf) - 34), 33) == 0);
	fclose(outfile);


	unsigned char salt[S2K_SALT_BYTES];
	unsigned char s2k_key[16];

	randombytes_buf(salt, S2K_SALT_BYTES);
	const char * pphrase = "ImGumbyAndYouAreNot";
	compute_gpg_s2k_key(pphrase, 32, salt, S2K_ITER_BYTE_COUNT, s2k_key);

	/*  Check to make sure that it computed the right key value  */
	SHA_CTX foo;
	SHA1_Init(&foo);
	char kbuf[64];
	int num_to_hash = S2K_ITER_BYTE_COUNT;
	len = S2K_SALT_BYTES + strlen(pphrase);
	memcpy(kbuf, salt, S2K_SALT_BYTES);
	memcpy(kbuf + S2K_SALT_BYTES, pphrase, len - S2K_SALT_BYTES);

	while (num_to_hash > len) {
		SHA1_Update(&foo, kbuf, len);
		num_to_hash -= len;
	}
	SHA1_Update(&foo, kbuf, num_to_hash);

	unsigned char dig1[SHA_DIGEST_LENGTH];
	SHA1_Final(dig1, &foo);
	assert(memcmp(dig1, s2k_key, SHA_DIGEST_LENGTH) == 0);

	gpg_now = time(NULL);

	retval = check_iron_keys(user_login);
	assert(retval == 0);

	gpg_public_key pka[2];
	bzero(pka, sizeof(pka));
	size_t c25519_pklen;
	unsigned char c25519_seckey[128];
	size_t c25519_sklen;
	retval = get_encryption_key(user_login, pka[0].key, &c25519_pklen, c25519_seckey, &c25519_sklen, pka[0].fp,
								pka[0].signer_fp);
	assert(retval == 0);
	assert(c25519_pklen == crypto_box_PUBLICKEYBYTES);

	/*  A valid public key.  */
	static unsigned char pkak[] = {
		0x96, 0xd7, 0xc8, 0x74, 0x27, 0xd3, 0x69, 0x4e, 0xfd, 0xbf, 0x04, 0x70, 0x4a, 0x36, 0xf8, 0x4e,
		0x3a, 0x4c, 0xb2, 0x36, 0xe6, 0x49, 0xce, 0x54, 0xfc, 0x96, 0xd6, 0x56, 0x5d, 0xad, 0xbc, 0x10
	};
	static unsigned char pkafp[] = {
		0xfc, 0x87, 0xc1, 0x23, 0xbb, 0x1d, 0x79, 0x32, 0x0b, 0x64, 0xac, 0x31, 0xe8, 0xb0, 0x1b, 0x03,
	   	0x0c, 0xdd, 0x21, 0x58
	};

	//  Directly manipulating the recipient list, so we don't need to create a user with a specific login
	//  and make sure that user has a .pubkey file.
	const gpg_public_key * tlist;
	int recip_ct = get_recipients(&tlist);
	assert(recip_ct == 1);
	strcpy(recipient_list[1].login, "fziffle");
	memcpy(recipient_list[1].key, pkak, sizeof(pkak));
	memcpy(recipient_list[1].fp, pkafp, sizeof(pkafp));
	memcpy(recipient_list[1].signer_fp, pkafp, sizeof(pkafp));
	num_recipients = 2;

	char enc_fname[PATH_MAX + 1];
	int outfd = write_gpg_encrypted_file("foob", 0, enc_fname);
	assert(outfd >= 0);
	close(outfd);
	rename("foob", "foob.pre_enc");
	char dec_fname[PATH_MAX + 1];
	write_gpg_decrypted_file(user_login, "foob.iron", dec_fname);

	// Try to construct a GPG public key signature and see why our signature is wrong
	// Grabbed some data from a run of gpg --gen-key (the experimental version 2.1.14-beta5)
	unsigned char n[] = {
		0xa4, 0xdb, 0xd0, 0xb5, 0xb2, 0x4a, 0xe7, 0x43, 0xb2, 0x5a, 0xd9, 0x1e, 0x4b, 0xa6, 0xca, 0x84,
		0x57, 0xf8, 0x2c, 0x03, 0x7e, 0x9d, 0xf9, 0xea, 0xec, 0x29, 0x8d, 0x15, 0xec, 0x4f, 0xbb, 0x23,
		0x4f, 0xf4, 0xda, 0x35, 0x96, 0x54, 0xb7, 0xd7, 0x11, 0xb5, 0x00, 0xa9, 0xca, 0x43, 0xaa, 0xf4,
		0x57, 0x2e, 0xb0, 0xe8, 0xca, 0xa2, 0x1e, 0x2c, 0x57, 0x69, 0x17, 0xfc, 0x74, 0x85, 0xb9, 0x5c,
		0x37, 0x67, 0x4f, 0x2f, 0x9d, 0x48, 0x43, 0x96, 0xe8, 0xb7, 0x19, 0xa1, 0xe1, 0x62, 0x3a, 0xe8,
		0xf9, 0xed, 0xc8, 0xbd, 0xda, 0x8e, 0x66, 0xb0, 0xae, 0x4d, 0xab, 0x28, 0x62, 0x4f, 0x0b, 0x29,
		0x74, 0xfc, 0x99, 0x9c, 0xe7, 0x6f, 0x69, 0x1e, 0x45, 0xc8, 0x43, 0x24, 0xd1, 0xb0, 0x67, 0x3e,
		0xd3, 0x13, 0x95, 0xf0, 0x06, 0x3d, 0x59, 0x77, 0x43, 0x70, 0x2e, 0x81, 0xba, 0x9d, 0x16, 0x00,
		0xb4, 0x86, 0xe4, 0x8d, 0x42, 0x51, 0x55, 0x4e, 0x96, 0x9e, 0xb9, 0x85, 0x1d, 0x46, 0xce, 0x16,
		0xf1, 0x93, 0x7d, 0x63, 0xf3, 0x2d, 0xb6, 0xea, 0x5f, 0x8d, 0x14, 0x4b, 0x94, 0x41, 0x2a, 0x43,
		0x81, 0x08, 0x79, 0x5e, 0x79, 0x02, 0x71, 0x6e, 0x64, 0xd7, 0x03, 0x78, 0x7e, 0xa9, 0x3c, 0x36,
		0x10, 0x67, 0xd3, 0xad, 0xd6, 0xbb, 0x10, 0x79, 0x25, 0x44, 0x12, 0x73, 0x7b, 0xc4, 0xf1, 0xce,
		0xa2, 0x7e, 0x65, 0x63, 0x30, 0x61, 0xd9, 0xc3, 0x70, 0x4b, 0x46, 0x46, 0x43, 0x21, 0x99, 0x69,
		0x23, 0x84, 0xca, 0x02, 0xf6, 0xcf, 0x8f, 0xcc, 0x58, 0x38, 0x0a, 0x7e, 0x64, 0x65, 0x26, 0x7e,
		0xc1, 0x04, 0x5c, 0x65, 0xf5, 0xa8, 0xa9, 0x3a, 0x11, 0x94, 0x53, 0x85, 0x8c, 0x9f, 0x9c, 0x54,
		0x89, 0x2d, 0x98, 0x51, 0x60, 0x8f, 0xa9, 0x71, 0x52, 0xdc, 0x76, 0x15, 0xef, 0x8f, 0x1a, 0x43
	};
	unsigned char e[] = {
		0x01, 0x00, 0x01
	};
	unsigned char d[] = {
		0x21, 0x5c, 0xa4, 0x87, 0x68, 0x8d, 0xd4, 0xf0, 0x33, 0xb3, 0x43, 0xd5, 0xe8, 0x2c, 0x58, 0x36,
		0x61, 0x11, 0x05, 0x63, 0x2d, 0xa7, 0xed, 0x8f, 0xf7, 0x7b, 0xcf, 0x23, 0xdd, 0x1f, 0x23, 0x79,
		0x59, 0x70, 0x6d, 0x0a, 0x44, 0x22, 0x5f, 0xd3, 0xc3, 0xaf, 0x13, 0xf3, 0xc8, 0x4d, 0x5a, 0x56,
		0xb9, 0x1f, 0xe7, 0x48, 0x2c, 0xdd, 0x92, 0xea, 0x99, 0x43, 0xd8, 0xc9, 0x4b, 0x91, 0x56, 0x3a,
		0x0d, 0xb2, 0x37, 0xe9, 0xa4, 0x54, 0x1f, 0xed, 0x75, 0xa9, 0xbc, 0x23, 0xb0, 0xd7, 0x2e, 0xa1,
		0xc0, 0x16, 0x39, 0x36, 0x06, 0x79, 0x23, 0xd9, 0xe4, 0x64, 0x2e, 0x5b, 0x6d, 0x4d, 0x9e, 0xae,
		0x24, 0x91, 0x0b, 0xcb, 0x1f, 0x60, 0xc1, 0xee, 0x90, 0xe3, 0x9e, 0x86, 0xe0, 0x72, 0x68, 0xea,
		0x63, 0x4f, 0xc6, 0xdb, 0x7c, 0x7f, 0xc4, 0xcf, 0xa8, 0x53, 0x96, 0xed, 0xc4, 0xe4, 0x8e, 0x33,
		0x82, 0x29, 0x57, 0xdd, 0x4c, 0x42, 0xd8, 0xdd, 0x7d, 0x62, 0xc1, 0xc1, 0xa4, 0x5b, 0xa5, 0xf6,
		0x16, 0x4f, 0x82, 0xc0, 0x31, 0xa0, 0x4c, 0x50, 0xab, 0x09, 0x2f, 0x9a, 0xae, 0x44, 0x2c, 0xab,
		0xd2, 0x81, 0xd0, 0x1d, 0xc4, 0x62, 0x95, 0x4d, 0xbd, 0xe6, 0xcc, 0xb4, 0x6d, 0xb6, 0x95, 0x5f,
		0x7d, 0x85, 0x7a, 0x41, 0x61, 0x43, 0x02, 0xb2, 0x09, 0x13, 0x6a, 0x85, 0x9a, 0xa4, 0x3c, 0xd7,
		0x01, 0xeb, 0xbd, 0x88, 0x81, 0x86, 0xca, 0xdf, 0x5a, 0xc2, 0x2f, 0x02, 0x57, 0x86, 0x2e, 0x10,
		0x9b, 0x8c, 0x99, 0xe3, 0x71, 0xea, 0x94, 0x9d, 0x18, 0x89, 0xde, 0xa1, 0xee, 0x30, 0x85, 0x21,
		0x03, 0x9e, 0xd4, 0x70, 0x6c, 0x7c, 0x92, 0xb8, 0x1c, 0x95, 0x77, 0xd8, 0xd3, 0x75, 0x7b, 0xc3,
		0x78, 0xf7, 0x64, 0xd6, 0xed, 0xcc, 0x8b, 0xa9, 0x46, 0x69, 0x4b, 0x4c, 0xeb, 0x84, 0x94, 0xa5
	};
	unsigned char p[] = {
		0xc8, 0xb4, 0x5a, 0xf4, 0xa1, 0x69, 0xc6, 0xb7, 0xf2, 0xee, 0x1d, 0x7f, 0xbc, 0xfa, 0x54, 0xcb,
		0x2f, 0x44, 0x0b, 0xe9, 0x46, 0x2c, 0xbe, 0x3b, 0x5b, 0xaf, 0xe1, 0x13, 0x0d, 0x65, 0xa2, 0xfb,
		0xa9, 0xed, 0xa2, 0x8a, 0x39, 0x9e, 0x58, 0x6e, 0x94, 0x09, 0xdb, 0xc8, 0x8d, 0xee, 0xf6, 0xa3,
		0xcc, 0xf1, 0xed, 0x7a, 0x51, 0x3a, 0x44, 0x01, 0x38, 0xc0, 0x2d, 0x53, 0x33, 0xd2, 0x31, 0x9c,
		0x01, 0xb5, 0x3a, 0xc8, 0xcb, 0x73, 0x9d, 0x70, 0x5f, 0x56, 0x28, 0xcc, 0x16, 0x77, 0xcb, 0xd3,
		0x40, 0xae, 0xa0, 0x34, 0x51, 0x39, 0x0a, 0xa1, 0x28, 0x31, 0xc4, 0x5f, 0xe7, 0x32, 0xea, 0x77,
		0x3b, 0x4d, 0x7f, 0x6f, 0x80, 0xfc, 0x41, 0xe7, 0x7c, 0xed, 0xb3, 0xac, 0x25, 0x35, 0xc8, 0x1f,
		0x8d, 0x22, 0xbf, 0xdc, 0x83, 0xe0, 0xcc, 0x94, 0x8b, 0x21, 0x3c, 0xaf, 0x90, 0x47, 0x8a, 0x2f
	};
	unsigned char q[] = {
		0xd2, 0x47, 0x42, 0x6c, 0xcc, 0xb7, 0xef, 0x67, 0x4b, 0x8a, 0x40, 0xa7, 0x83, 0xec, 0xf5, 0x6a,
		0x99, 0x68, 0x06, 0x1d, 0x4f, 0xcf, 0xae, 0xfa, 0x3f, 0xe8, 0x4e, 0x55, 0x74, 0x43, 0x27, 0xc5,
		0x8d, 0xe5, 0xb7, 0x58, 0x58, 0x35, 0x12, 0xb0, 0xd3, 0x5e, 0x29, 0xd0, 0xd7, 0xd6, 0x35, 0xe5,
		0x70, 0xb2, 0x59, 0x75, 0xa1, 0xe3, 0xbe, 0x8f, 0x61, 0x82, 0x45, 0x8f, 0xac, 0x41, 0xc9, 0x10,
		0x03, 0x79, 0x95, 0x39, 0xc1, 0x42, 0x31, 0xaa, 0xa8, 0x9d, 0xe9, 0x25, 0xc6, 0x00, 0x95, 0xe9,
		0x51, 0xb2, 0x5b, 0xb9, 0x03, 0x2f, 0x7e, 0x05, 0xfa, 0x9f, 0xeb, 0x3a, 0x2e, 0x96, 0x6b, 0x0f,
		0x33, 0x2d, 0xfc, 0xd6, 0x02, 0x75, 0xd9, 0xc3, 0x88, 0x86, 0xff, 0x9f, 0x6e, 0xb9, 0x1c, 0x1e,
		0x94, 0x5a, 0x07, 0x3f, 0xd0, 0xe3, 0xc3, 0x1b, 0x4c, 0xbb, 0xf4, 0x20, 0xea, 0x5d, 0x30, 0x2d
	};
	unsigned char u[] = {
		0x79, 0x90, 0x3a, 0xc8, 0xeb, 0x97, 0x25, 0x9d, 0xae, 0xa2, 0xb0, 0x83, 0x77, 0xc9, 0x2f, 0x9b,
		0x40, 0x04, 0x8c, 0xb1, 0xba, 0x13, 0xa6, 0x29, 0x78, 0x18, 0xd4, 0x00, 0xd1, 0x27, 0x39, 0x7d,
		0x5f, 0x15, 0x16, 0xc5, 0xa9, 0xa4, 0xa3, 0xa4, 0x1a, 0xcc, 0xc8, 0x5b, 0x86, 0xcb, 0x85, 0x0f,
		0x47, 0xb9, 0xc5, 0xda, 0x70, 0x56, 0x89, 0x83, 0x6d, 0x19, 0xe6, 0x31, 0x2f, 0xda, 0x2e, 0x7b,
		0x39, 0x0b, 0xa8, 0x31, 0xdc, 0xba, 0x68, 0xff, 0x01, 0x34, 0x7d, 0x6c, 0xed, 0xf3, 0x24, 0x4f,
		0xc1, 0x31, 0x11, 0x55, 0x07, 0x11, 0x7b, 0x27, 0x83, 0x73, 0x98, 0xdf, 0x92, 0x95, 0x4b, 0x00,
		0xcf, 0xe4, 0x2d, 0x13, 0xdd, 0x1f, 0x9b, 0x2f, 0x18, 0x0c, 0xe8, 0xa4, 0x52, 0xfc, 0xb3, 0x80,
		0xde, 0xb6, 0x3f, 0x70, 0x08, 0xb2, 0xdd, 0xe2, 0x7d, 0x8e, 0x0d, 0xd7, 0x54, 0x37, 0x32, 0x91
	};
	unsigned char sighash[] = {
		0x53, 0x6e, 0xc3, 0x18, 0x9b, 0xd2, 0x5f, 0x8c, 0xc3, 0x39, 0xde, 0xe1, 0xa6, 0x88, 0x04, 0x64,
		0xd2, 0x69, 0xb4, 0x2d, 0xe0, 0x8b, 0x93, 0x53, 0x57, 0xd4, 0xa5, 0x9d, 0x1b, 0xd7, 0x02, 0x74,
		0x10, 0x31, 0xe2, 0x34, 0x29, 0x79, 0xd3, 0xc4, 0x41, 0x5b, 0x8f, 0x52, 0x66, 0x2f, 0xc3, 0x5d,
		0x0c, 0xe7, 0xef, 0x10, 0x50, 0xf0, 0xfe, 0x09, 0x68, 0x17, 0x9b, 0xe7, 0xf3, 0x14, 0x47, 0xc5
	};
	unsigned char finalsig[] = {
		0x18, 0x6d, 0xbe, 0x32, 0x5c, 0x1a, 0x40, 0x53, 0xd8, 0x80, 0x07, 0x2c, 0xe1, 0x6e, 0x06, 0x01,
		0x6a, 0x73, 0xd5, 0x6c, 0x6c, 0xa9, 0xa9, 0xb3, 0xe5, 0xe7, 0x84, 0xd1, 0x9c, 0x06, 0x5e, 0x51,
		0xff, 0x70, 0xf9, 0x76, 0xcf, 0x21, 0x4b, 0xed, 0xc8, 0x14, 0xf3, 0x95, 0xb5, 0x00, 0x11, 0x60,
		0x44, 0x40, 0x7c, 0xbe, 0xf7, 0x97, 0xe1, 0x0c, 0xca, 0x68, 0x7e, 0x69, 0x82, 0x83, 0x55, 0x91,
		0x7d, 0x9a, 0x65, 0x2b, 0x37, 0x3c, 0x0d, 0x9b, 0x2e, 0xd1, 0x20, 0x71, 0x88, 0xa5, 0x4e, 0x8f,
		0x00, 0xe5, 0xa9, 0x85, 0x04, 0x18, 0x7e, 0xf4, 0x19, 0x5a, 0x2d, 0x2c, 0x90, 0x40, 0x29, 0x47,
		0x73, 0xdf, 0x5b, 0xc7, 0x06, 0xfc, 0x83, 0x06, 0xdc, 0x69, 0x85, 0x21, 0x5e, 0xaa, 0x6d, 0x23,
		0x5e, 0xc6, 0xaa, 0x26, 0xf5, 0x34, 0x3e, 0x84, 0xdf, 0x61, 0x83, 0x63, 0x12, 0x67, 0x07, 0xf8,
		0xb4, 0xf9, 0x42, 0x26, 0x49, 0x84, 0x03, 0xe2, 0x87, 0x9c, 0x7b, 0xa3, 0xbc, 0x03, 0xc9, 0x0b,
		0x44, 0x33, 0xd3, 0xe9, 0x4f, 0x42, 0xc4, 0xa0, 0x02, 0x6a, 0x07, 0x1c, 0x0f, 0x60, 0x7b, 0x96,
		0x87, 0xb9, 0xd6, 0x05, 0x68, 0xc4, 0x40, 0x35, 0x68, 0x67, 0xf0, 0xcd, 0xa0, 0xb0, 0xe2, 0xe3,
		0x9f, 0x61, 0xbc, 0x48, 0x49, 0x73, 0x8c, 0x30, 0x4b, 0x18, 0x71, 0x7b, 0x0a, 0x35, 0x88, 0x48,
		0x70, 0x4c, 0xee, 0x5a, 0xcb, 0x2e, 0xab, 0x4d, 0x63, 0x1b, 0x64, 0xb1, 0x43, 0x49, 0xfe, 0xb4,
		0xe2, 0x50, 0x61, 0x67, 0x51, 0x6f, 0xed, 0x1b, 0x21, 0x69, 0x44, 0xa0, 0x78, 0x3f, 0x05, 0x40,
		0x43, 0xf3, 0x0e, 0x65, 0x63, 0x55, 0x7d, 0x8e, 0x83, 0x5b, 0x10, 0x15, 0xbe, 0x1d, 0xa9, 0xe6,
		0x0a, 0xdb, 0x95, 0x26, 0x8e, 0x25, 0x1a, 0x79, 0x98, 0x9d, 0x63, 0xa8, 0x40, 0xd4, 0x00, 0x2f
	};


	gpg_message pk1;
	gpg_message uid1;
	gpg_message sig1;

	pk1.data = sshbuf_new();
	uid1.data = sshbuf_new();
	sig1.data = sshbuf_new();

	pk1.tag = GPG_TAG_PUBLIC_KEY;
	sshbuf_put_u8(pk1.data, 4);				// version
	sshbuf_put_u32(pk1.data, 1467164339);	// timestamp
	sshbuf_put_u8(pk1.data, 1);				// PK algo
	BIGNUM * bn_n = BN_new();
	BN_bin2bn(n, sizeof(n), bn_n);
	put_bignum(pk1.data, bn_n);
	BIGNUM * bn_e = BN_new();
	BN_bin2bn(e, sizeof(e), bn_e);
	put_bignum(pk1.data, bn_e);
	pk1.len = sshbuf_len(pk1.data);

	uid1.tag = GPG_TAG_USERID;
	sshbuf_put(uid1.data, "Bob Wall <bobwall@icl>", 22);
	uid1.len = sshbuf_len(uid1.data);

	sig1.tag = GPG_TAG_SIGNATURE;
	sshbuf_put_u8(sig1.data, 4);			// version
	sshbuf_put_u8(sig1.data, 19);			// sig class
	sshbuf_put_u8(sig1.data, 1);			// PK algo
	sshbuf_put_u8(sig1.data, 10);			// hash algo
	sshbuf_put_u16(sig1.data, 33);			// hashed len
	sshbuf_put_u8(sig1.data, 5);			// hashed subpkt len
	sshbuf_put_u8(sig1.data, 2);			// signature creation subpkt
	sshbuf_put_u32(sig1.data, 1467164339);  // timestamp
	sshbuf_put_u8(sig1.data, 2);			// hashed subpkt len
	sshbuf_put_u8(sig1.data, 27);			// key flags subpkt
	sshbuf_put_u8(sig1.data, 3);			// key flags
	sshbuf_put_u8(sig1.data, 5);			// hashed subpkt len
	sshbuf_put_u8(sig1.data, 11);			// pref sym key subpkt
	sshbuf_put_u8(sig1.data, 9);
	sshbuf_put_u8(sig1.data, 8);
	sshbuf_put_u8(sig1.data, 7);
	sshbuf_put_u8(sig1.data, 3);
	sshbuf_put_u8(sig1.data, 5);			// hashed subpkt len
	sshbuf_put_u8(sig1.data, 21);			// pref hash subpkt
	sshbuf_put_u8(sig1.data, 10);
	sshbuf_put_u8(sig1.data, 9);
	sshbuf_put_u8(sig1.data, 8);
	sshbuf_put_u8(sig1.data, 11);
	sshbuf_put_u8(sig1.data, 5);			// hashed subpkt len
	sshbuf_put_u8(sig1.data, 22);			// pref compression subpkt
	sshbuf_put_u8(sig1.data, 2);
	sshbuf_put_u8(sig1.data, 3);
	sshbuf_put_u8(sig1.data, 1);
	sshbuf_put_u8(sig1.data, 0);
	sshbuf_put_u8(sig1.data, 2);			// hashed subpkt len
	sshbuf_put_u8(sig1.data, 30);			// features subpkt
	sshbuf_put_u8(sig1.data, 1);
	sshbuf_put_u8(sig1.data, 2);			// hashed subpkt len
	sshbuf_put_u8(sig1.data, 23);			// key server prefs subpkt
	sshbuf_put_u8(sig1.data, 128);

	sig1.len = sshbuf_len(sig1.data);

	SHA512_CTX  ctx;
	SHA512_Init(&ctx);

	len = generate_tag_and_size(pk1.tag, pk1.len, buf);
	SHA512_Update(&ctx, buf, len);
	SHA512_Update(&ctx, sshbuf_ptr(pk1.data), sshbuf_len(pk1.data));
	buf[0] = 0xb4;
	buf[1] = 0x00;
	buf[2] = 0x00;
	buf[3] = 0x00;
	buf[4] = uid1.len;
	SHA512_Update(&ctx, buf, 5);
	SHA512_Update(&ctx, sshbuf_ptr(uid1.data), sshbuf_len(uid1.data));

	SHA512_Update(&ctx, sshbuf_ptr(sig1.data), sshbuf_len(sig1.data));

	int hash_len = sshbuf_len(sig1.data);
	buf[0] = GPG_KEY_VERSION;
	buf[1] = 0xff;
	buf[2] = (unsigned char) ((hash_len >> 24) & 0xff);
	buf[3] = (unsigned char) ((hash_len >> 16) & 0xff);
	buf[4] = (unsigned char) ((hash_len >> 8) & 0xff);
	buf[5] = (unsigned char) (hash_len & 0xff);
	SHA512_Update(&ctx, buf, 6);

	unsigned char digest[SHA512_DIGEST_LENGTH];
	SHA512_Final(digest, &ctx);

	assert(sizeof(sighash) == SHA512_DIGEST_LENGTH);
	assert(memcmp(digest, sighash, SHA512_DIGEST_LENGTH) == 0);

	// Now add unhashed packets
	sshbuf_put_u16(sig1.data, 10);			// unhashed len
	sshbuf_put_u8(sig1.data, 9);			// unhashed subpkt len
	sshbuf_put_u8(sig1.data, 16);			// issuer subpkt
	sshbuf_put_u32(sig1.data, 0xa9a71472);
	sshbuf_put_u32(sig1.data, 0xe392bf5d);
	sshbuf_put_u8(sig1.data, digest[0]);
	sshbuf_put_u8(sig1.data, digest[1]);

	unsigned char key_fp[GPG_KEY_FP_LEN];
	compute_gpg_key_fingerprint(&pk1, key_fp);

	struct sshkey key;
	bzero(&key, sizeof(key));

	key.type = KEY_RSA;
	key.rsa = RSA_new();
	key.rsa->n = BN_new();
	BN_bin2bn(n, sizeof(n), key.rsa->n);
	key.rsa->e = BN_new();
	BN_bin2bn(e, sizeof(e), key.rsa->e);
	key.rsa->p = BN_new();
	BN_bin2bn(p, sizeof(p), key.rsa->p);
	key.rsa->q = BN_new();
	BN_bin2bn(q, sizeof(q), key.rsa->q);
	key.rsa->d = BN_new();
	BN_bin2bn(d, sizeof(d), key.rsa->d);
	key.rsa->iqmp = BN_new();
	BN_bin2bn(u, sizeof(u), key.rsa->iqmp);

	BIGNUM * sig = compute_rsa_signature(digest, SHA512_DIGEST_LENGTH, &key);
	unsigned char rsa_sig[512];
	int sig_len = BN_bn2bin(sig, rsa_sig);
	assert(sig_len == sizeof(finalsig));
	assert(memcmp(rsa_sig, finalsig, sig_len));

	unsigned char keygrip[SHA_DIGEST_LENGTH];
	char hexgrip [2 * SHA_DIGEST_LENGTH + 1];
	unsigned char n1[] = {
		0x00,
		0xd3, 0x31, 0xa4, 0x76, 0x9d, 0xfe, 0x89, 0x74, 0x82, 0xa4, 0xcc, 0xe5, 0x58, 0xc1, 0xf3, 0xcc,
		0xe7, 0xf8, 0x3a, 0x0b, 0xbb, 0x3a, 0x93, 0x6b, 0x0e, 0xaa, 0xe2, 0x92, 0xaf, 0x6a, 0x98, 0x75,
		0xce, 0x0c, 0xca, 0x72, 0x26, 0x0f, 0x7b, 0x7c, 0xde, 0x3c, 0xf6, 0xca, 0xf3, 0x9b, 0x21, 0x37,
		0x92, 0x24, 0x88, 0xdd, 0x95, 0xa0, 0xfe, 0x40, 0x5a, 0x50, 0xef, 0x49, 0x77, 0x8c, 0x56, 0xab,
		0x4b, 0x2a, 0x35, 0x3c, 0x5e, 0x58, 0x43, 0xee, 0x98, 0x35, 0x4a, 0xa2, 0x4f, 0xdd, 0x89, 0x6b,
		0xa3, 0x2d, 0x8a, 0xcb, 0xd8, 0x42, 0x3c, 0x26, 0xa2, 0xae, 0x8f, 0xb9, 0xc0, 0xb2, 0xab, 0x37,
		0xda, 0x61, 0x44, 0xf0, 0x16, 0x53, 0xc9, 0x1d, 0xe5, 0x1c, 0xe1, 0x3c, 0x33, 0x71, 0x2f, 0x8d,
		0x31, 0xb2, 0x8c, 0x5e, 0x90, 0xcb, 0xb0, 0x30, 0xa8, 0xd3, 0x33, 0x29, 0x28, 0x6f, 0x10, 0x3d,
		0xc4, 0xc7, 0x68, 0x12, 0xb8, 0x88, 0x52, 0xed, 0x6f, 0x91, 0xf3, 0xc0, 0x58, 0xd5, 0x38, 0x7d,
		0x52, 0x4d, 0xe6, 0x43, 0x2f, 0x1b, 0xaa, 0x2e, 0xe1, 0x9d, 0x91, 0xa1, 0x1c, 0x41, 0x42, 0x56,
		0xcd, 0x9a, 0x69, 0x17, 0x7b, 0x3c, 0x83, 0x5e, 0x42, 0xb2, 0x81, 0xdf, 0x15, 0x12, 0x4b, 0xef,
		0xbd, 0x99, 0x11, 0x35, 0xcb, 0xa5, 0xc3, 0xb3, 0x07, 0xd3, 0x31, 0x5f, 0x60, 0x58, 0x17, 0x2e,
		0xe6, 0x83, 0x37, 0x01, 0x8b, 0xc2, 0xda, 0x1b, 0x54, 0xcf, 0x80, 0x44, 0xa9, 0xb6, 0x2c, 0xba,
		0x33, 0x71, 0x0a, 0x1e, 0xd3, 0xda, 0xd7, 0xa4, 0x37, 0xf9, 0x3f, 0x41, 0xf0, 0x86, 0x55, 0xa2,
		0x6f, 0x2a, 0xc8, 0xf7, 0xad, 0x76, 0x6a, 0x2c, 0x06, 0x00, 0x0a, 0xeb, 0xf7, 0xc1, 0x7b, 0xa8,
		0xe0, 0x58, 0x80, 0x37, 0xf3, 0x4c, 0xb2, 0x28, 0x3c, 0xb2, 0x4a, 0xfc, 0x86, 0xf2, 0xe7, 0x9b
	};

	unsigned char q1[] = {
		0xa4, 0x44, 0x34, 0xa8, 0x30, 0xa3, 0x34, 0x05, 0x1d, 0x14, 0x96, 0x33, 0x59, 0x6b, 0x7b, 0x4a,
		0xa9, 0x93, 0x80, 0x77, 0x76, 0xff, 0x70, 0x58, 0x97, 0x31, 0xd6, 0x5e, 0xe7, 0x7d, 0x2b, 0x44
	};
	unsigned char q2[] = {
		0xdb, 0xd2, 0x7d, 0xe0, 0x44, 0x39, 0x00, 0x88, 0x72, 0xd4, 0x9d, 0x9e, 0x3e, 0xa6, 0x6a, 0x5d,
		0x26, 0x08, 0x80, 0x9f, 0x2b, 0xe5, 0x78, 0x9d, 0x8b, 0x68, 0xe9, 0x17, 0x72, 0x06, 0x5d, 0x24
	};
	unsigned char q3[] = {
		0x8d, 0xcf, 0x86, 0x3e, 0xe0, 0xd6, 0x00, 0x76, 0x3a, 0xf1, 0xc7, 0x7a, 0x41, 0x5f, 0x26, 0xa4,
		0xba, 0x5e, 0xa1, 0xb9, 0xbe, 0xaf, 0xdb, 0x42, 0x4f, 0xaf, 0x7f, 0x8f, 0xb2, 0x23, 0x2e, 0x42
	};
	
	compute_gpg_sha1_hash_chars(n1, sizeof(n1), keygrip);
	hex2str(keygrip, sizeof(keygrip), hexgrip);
	//assert(strcmp(hexgrip, "D482F40823188E390A3AB73743921CCCB3C96CA2") == 0);
	generate_gpg_curve25519_keygrip(q1, sizeof(q1), keygrip);
	hex2str(keygrip, sizeof(keygrip), hexgrip);
	//assert(strcmp(hexgrip, "E762A55B55DF1FD9B63774244D8AB5290622B1D7") == 0);
	generate_gpg_curve25519_keygrip(q2, sizeof(q2), keygrip);
	hex2str(keygrip, sizeof(keygrip), hexgrip);
	//assert(strcmp(hexgrip, "DCF1C52E13C421BBAEC1D37F86D30B2CF366971F") == 0);
	generate_gpg_curve25519_keygrip(q3, sizeof(q3), keygrip);
	hex2str(keygrip, sizeof(keygrip), hexgrip);
	//assert(strcmp(hexgrip, "2B4B3A5870A8997BB613E6BDC469F3BC87FF078C") == 0);

	generate_gpg_rsa_seckey(&key, "abc123");


	unsigned char fake_d[] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xde
	};
	struct sshkey fake_key;
	bzero(&fake_key, sizeof(fake_key));

	fake_key.type = KEY_RSA;
	fake_key.rsa = RSA_new();
	fake_key.rsa->d = BN_new();
	BN_bin2bn(fake_d, sizeof(fake_d), fake_key.rsa->d);
	char * pp = generate_gpg_passphrase_from_rsa(&fake_key);

	SHA256_CTX fake_ctx;
	SHA256_Init(&fake_ctx);
	for (int fake_ct = 0; fake_ct < 256; fake_ct++) {
		SHA256_Update(&fake_ctx, fake_d, sizeof(fake_d));
	}
	unsigned char fake_dig[SHA256_DIGEST_LENGTH];
	char fake_pp[50];
	SHA256_Final(fake_dig, &fake_ctx);
	uuencode(fake_dig, sizeof(fake_dig), fake_pp, sizeof(fake_pp));
	assert(strcmp(pp, fake_pp) == 0);

	/*  A keypair generated by GPG.  */
	static unsigned char pub_g[crypto_box_PUBLICKEYBYTES] = {
		// Reversed
		/*
		0x22, 0xaf, 0x7b, 0x9d, 0xc5, 0x49, 0x43, 0x38, 0x81, 0x1d, 0xbb, 0x99, 0x50, 0x24, 0x11, 0x2f,
	    0xb0, 0xaf, 0xef, 0x15, 0xb3, 0x81, 0x08, 0x53, 0x47, 0x23, 0xe6, 0x7c, 0xb5, 0x72, 0xa0, 0xe4
		*/
    	0xe4, 0xa0, 0x72, 0xb5, 0x7c, 0xe6, 0x23, 0x47, 0x53, 0x08, 0x81, 0xb3, 0x15, 0xef, 0xaf, 0xb0,
	   	0x2f, 0x11, 0x24, 0x50, 0x99, 0xbb, 0x1d, 0x81, 0x38, 0x43, 0x49, 0xc5, 0x9d, 0x7b, 0xaf, 0x22
	};
	static unsigned char sec_g[crypto_box_SECRETKEYBYTES] = {
		// Reversed
		0xd0, 0x1c, 0xb0, 0x22, 0x9f, 0xd8, 0xe6, 0xff, 0x14, 0xb1, 0xd5, 0xb6, 0x3f, 0x66, 0x86, 0x1e,
	    0x10, 0x5b, 0xff, 0x17, 0xad, 0x64, 0x0f, 0x5f, 0x55, 0x1d, 0x01, 0x76, 0x06, 0x3b, 0x05, 0x6c
		/*
		0x6c, 0x05, 0x3b, 0x06, 0x76, 0x01, 0x1d, 0x55, 0x5f, 0x0f, 0x64, 0xad, 0x17, 0xff, 0x5b, 0x10,
	   	0x1e, 0x86, 0x66, 0x3f, 0xb6, 0xd5, 0xb1, 0x14, 0xff, 0xe6, 0xd8, 0x9f, 0x22, 0xb0, 0x1c, 0xd0
		*/
	};
	unsigned char pub_s[crypto_box_PUBLICKEYBYTES];
	unsigned char sec_s[crypto_box_SECRETKEYBYTES];

	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	unsigned char sk[crypto_box_PUBLICKEYBYTES];

	memset(sk, 0xff, sizeof(sk));
    clamp_and_reverse_seckey(sk);
	assert(sk[0] == 0x7f);
	assert(sk[31] == 0xf8);
	memset(sk, 0x00, sizeof(sk));
    clamp_and_reverse_seckey(sk);
	assert(sk[0] == 0x40);
	assert(sk[31] == 0x00);
	memset(sk, 0xaa, sizeof(sk));
    clamp_and_reverse_seckey(sk);
	assert(sk[0] == 0x6a);
	assert(sk[31] == 0xa8);
	memset(sk, 0x55, sizeof(sk));
    clamp_and_reverse_seckey(sk);
	assert(sk[0] == 0x55);
	assert(sk[31] == 0x50);

	crypto_box_keypair(pub_s, sec_s);

	// Deep in the bowels of the key generation, the secret key was "clamped" before generating the public
	// key, but it didn't actually change the bits in the secret key it returned. We'll go ahead and do that,
	// to avoid confusion.
	sec_s[0] &= 0xf8;			//  Zero lowest three bits of secret key - part of "clamping"
	sec_s[31] &= 0x7f;			//  Zero highest bit
	sec_s[31] |= 0x40;			//  Set next-to-highest bit


	crypto_scalarmult_base(pk, sec_s);
	assert(memcmp(pub_s, pk, sizeof(pub_s)) == 0);

	crypto_scalarmult_base(pk, sec_g);
	assert(memcmp(pub_g, pk, sizeof(pub_g)) == 0);

	unsigned char sk8[] = {
		0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
		0x10, 0x11, 0x10, 0x11, 0x10, 0x11, 0x10, 0x11, 0x10, 0x11, 0x10, 0x11, 0x10, 0x11, 0x10, 0x11
	};
	unsigned char pk8[33];
	unsigned char sk9[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
	};
	unsigned char pk9[33];
	unsigned char sec8[40];
	unsigned char sec9[40];
	crypto_scalarmult_base(pk8 + 1, sk8);
	crypto_scalarmult_base(pk9 + 1, sk9);
	*pk8 = 0x40;
	*pk9 = 0x40;
	crypto_scalarmult_curve25519(sec8, sk9, pk8 + 1);
	crypto_scalarmult_curve25519(sec9, sk8, pk9 + 1);

	assert(memcmp(sec8, sec9, 32) == 0);

	return 0;
}

void
tests(void)
{
	// Initialization
	ssh_malloc_init();

	struct passwd * user_pw = getpwuid(getuid());
	if (user_pw == NULL) {
		fprintf(stderr, "Unable to determine current user's login\n\n");
	} else {
		user_login = xstrdup(user_pw->pw_name);
	}

	test_tags();
	test_msgs();
}

#endif
