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
#include <string.h>
#include <libgen.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sftp-common.h"
#include "openbsd-compat/openbsd-compat.h"
#include "openssl/bn.h"
#include "authfd.h"
#include "authfile.h"
#include "key.h"
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
#include "iron-common.h"
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

#define DECRYPT_CHUNK_SIZE 		8 * 1024//  # bytes of encrypted file to read at a time

#define SSH_KEY_FNAME			"id_rsa"
#define IRON_SSH_KEY_FNAME		"id_rsa.iron"
#define SSH_KEY_PUB_EXT			".pub"
#define GPG_PUBLIC_KEY_FNAME	"pubring.gpg"
#define GPG_SECKEY_SUBDIR		"private-keys-v1.d"
#define GPG_KEY_VERSION			4		//  Current version for public and secret key packets
#define GPG_SIG_VERSION			4		//  Current version for signature packets
#define GPG_PKESK_VERSION		3		//  Current version for public key encrypted session key packets
#define GPG_OPS_VERSION			3		//  Current version for one pass signature packets
#define GPG_SEIPD_VERSION		1		//  Current version for symmetrically encrypted integrity protected data pkts

#define MAX_PASSPHRASE_RETRIES	3		//  Number of times user is prompted to enter passphrase to access SSH key
#define PRE_ENC_PPHRASE_BYTES	33		//  Number of bytes of RSA signature to use as passphrase (pre-base64 encoding)
#define PPHRASE_LEN				4 * ((PRE_ENC_PPHRASE_BYTES + 2) / 3) + 1		//  +1 for null terminator

//  Some constants related to the header of a GPG message - the tag byte and length.
#define GPG_TAG_MARKER_BIT		0x80	//  Tag byte should ALWAYS have high bit set
#define GPG_TAG_FORMAT_BIT		0x40	//  Next bit of tag indicates old (0) or new (1) format
#define GPG_TAG_OF_MASK			0x3c	//  In old format, bits 2-5 are tag value
#define GPG_TAG_OF_SHIFT		2		//  In old format, shift of last two bits (lentype) got get tag
#define GPG_TAG_OF_LENTYPE_MASK	0x03	//  In old format, last two bits indicate type of following length
#define GPG_TAG_NF_MASK			0x3f	//  In new format, low 6 bits are tag value
#define GPG_TAG_NF_MASK			0x3f	//  In new format, low 6 bits are tag value
#define GPG_OF_LENTYPE_SHORT	0
#define GPG_OF_LENTYPE_MEDIUM	1
#define GPG_OF_LENTYPE_LONG		2
#define GPG_OF_LENTYPE_INDETERMINATE 3	//  Special size value to indicate length must be determined externally to pkt
#define GPG_OF_LEN_SHORT		1
#define GPG_OF_LEN_MEDIUM		2
#define GPG_OF_LEN_LONG			4
#define GPG_OF_LEN_INDETERMINATE -1		//  Special size value to indicate length must be determined externally to pkt
#define GPG_NF_LEN_THRESHOLD1	0xc0	//  New format lengths shorter than 0xc0 (192) bytes are in one byte
#define GPG_NF_LEN_SHORT		1
#define GPG_NF_LEN_THRESHOLD2	0xe0	//  New format lengths that start with a value between 0xc0 and 0xdf (223)
										//      are two bytes long
#define GPG_NF_LEN_MEDIUM		2
#define GPG_NF_LEN_LIMIT_MEDIUM 0x20c0	//  Maximum length that can be encoded into the medium (2-byte) format using
										//		that goofy encoding algorithm
#define GPG_NF_LEN_THRESHOLD4	0xff	//  New format lengths that start with a value of 0xff are five bytes
										//		long - 0xff is ignored, and next four bytes are length
#define GPG_NF_LEN_LONG			5
#define GPG_NF_LEN_PARTIAL		1

#define GPG_OF_TAG_LIMIT		15		//  Old format tags need to fit into 4 bits in tag byte
#define GPG_NF_TAG_LIMIT		63		//  New format tags need to fit into 6 bits in tag byte

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

/*  Public keys (signing and encryption) and associated info for the specified login.  */
typedef struct gpg_public_key {
	char			login[MAX_LOGIN_LEN + 1];
	Key				rsa_key;
	u_char			key[crypto_box_PUBLICKEYBYTES];
	u_char			fp[GPG_KEY_FP_LEN];
	u_char			signer_fp[GPG_KEY_FP_LEN];
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
static char   * user_login;		//  Stores the login of the user running the process. Set at initialization.


static int		inited = 0;		//	Indicates that the process has initialized everything needed for IronSFTP

/*  Curve 25519 parameters P, A, B, N, G_X, G_Y, H)
    P   = "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED",		prime
    A   = "0x01DB41",																A coefficient of curve
    B   = "0x01",																	B coefficient of curve
    N   = "0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED",		order of base point
    G_X = "0x0000000000000000000000000000000000000000000000000000000000000009",		base point X
    G_Y = "0x20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9",		base point Y
    H   = "0x08"																	cofactor
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

/*  Forward function declaration for all static functions. Declared here so we can arrange in groups regardless of
 *  which functions call others.  */

//  Utility funcs
static int		initialize(void);
static void		hex2str(const u_char * hex, int hex_len, char * str);
static int		str2hex(const char * str, u_char * hex, int hex_len);
static void		int_to_buf(int val, u_char * buf);
static u_int32_t buf_to_int(const u_char * buf);
static int		put_bignum(struct sshbuf * buf, const BIGNUM * bignum);
static void		put_num_sexpr(struct sshbuf * buf, const u_char * bstr, int bstr_len);
static void		populate_ssh_dir(const char * const login, char * ssh_dir);
static const char * get_user_ssh_dir(const char * const login);
static char *	check_seckey_dir(const char * ssh_dir);
static int		hashcrypt(SHA_CTX * mdc_ctx, SHA256_CTX * sig_ctx, EVP_CIPHER_CTX * aes_ctx,
						  const u_char * input, int size, u_char * output);
static void		reverse_byte_array(const u_char * src, u_char * dst, unsigned int len);
static void		reverse_byte_array_in_place(u_char * arr, unsigned int len);

//  GPG utility funcs
static void		clamp_and_reverse_seckey(u_char * sk);
static void		compute_gpg_sha1_hash_sshbuf(const struct sshbuf * buf, u_char * hash);
static void		compute_gpg_sha1_hash_chars(const u_char * bstr, int bstr_len, u_char * hash);
static void		compute_gpg_s2k_key(const char * passphrase, int key_len, const u_char * salt,
									int bytes_to_hash, u_char * key);
static int		generate_gpg_passphrase_from_rsa(const Key * ssh_key, char * passphrase);
static void		compute_gpg_key_fingerprint(const gpg_message * pubkey_pkt, u_char * key_fp);
static BIGNUM * compute_rsa_signature(const u_char * digest, size_t digest_len, const Key * key);
static void		generate_gpg_kek(const u_char * fp, const u_char * shared_point, u_char * kek);
static struct sshbuf * encrypt_gpg_sec_parms(const struct sshbuf * buf, const u_char * passphrase,
											 u_char * salt, u_char * iv, size_t iv_len);
static int		encrypt_gpg_key_frame(const u_char * sym_key_frame, int frame_len, const u_char * key,
									  u_char * enc_frame);
static int		decrypt_gpg_key_frame(const u_char * enc_frame, int frame_len, const u_char * key,
									  u_char * frame);

//  GPG funcs to build / extract pieces of packets
static int		put_gpg_message(FILE * outfile, const gpg_message * msg);
static int		get_size_new_format(FILE *infile, ssize_t * size);
static int		get_size_old_format(FILE * infile, u_char len_type, ssize_t * size);
static int		get_tag_and_size(FILE * infile, gpg_tag * tag, ssize_t * size);
static int		extract_size_new_format(const u_char * buf, ssize_t * size);
static int		extract_size_old_format(const u_char * buf, u_char len_type, ssize_t * size);
static int		extract_tag_and_size(const u_char * buf, gpg_tag * tag, ssize_t * size);
static int		generate_tag_and_size(gpg_tag tag, ssize_t size, u_char * buf);
static void		generate_gpg_protected_at(char * str);
static struct sshbuf * generate_gpg_rsa_pub_parms(const Key * ssh_key);
static void		put_parm_in_sexpr(struct sshbuf * buf, char parm_name, BIGNUM * bn);
static int		get_parm_from_sexpr(const u_char * buf, char parm_name, BIGNUM ** bn);
static struct sshbuf * generate_gpg_rsa_sec_parms(const Key * ssh_key);
static struct sshbuf * generate_gpg_rsa_seckey(const Key * ssh_key, const u_char * passphrase);
static void		generate_gpg_rsa_keygrip(const Key * rsa_key, u_char * grip);
static void		generate_gpg_curve25519_keygrip(const u_char * q, int q_len, u_char * grip);
static struct sshbuf * generate_gpg_curve25519_pub_parms(const u_char * q, int q_len);
static struct sshbuf * generate_gpg_curve25519_sec_parms(const u_char * d, int d_len);
static struct sshbuf * generate_gpg_curve25519_seckey(const u_char * q, int q_len, const u_char * d,
													  int d_len, const u_char * passphrase);
static int		generate_gpg_sym_key_frame(u_char * sym_key_frame);
static void		generate_curve25519_ephem_shared_secret(const u_char * recip_pk, u_char * ephem_pk,
														u_char *secret);
static void		generate_curve25519_shared_secret(const u_char * sec_key, const u_char * pub_key,
												  u_char * secret);
static int		encrypt_input_file(FILE * infile, FILE * outfile, SHA_CTX * mdc_ctx, SHA256_CTX * sig_ctx,
	   							   EVP_CIPHER_CTX * aes_ctx);

static int		extract_gpg_rsa_pubkey(const struct sshbuf * buf, Key * rsa_key);
static u_char * decrypt_gpg_sec_parms(const u_char * enc_data, int len, const Key * rsa_pubkey, const u_char * salt, 
									  int hash_bytes, const u_char * iv);
static u_char * extract_gpg_sec_parms(char pub_parm_name, const char * key_name, const u_char * buf, int buf_len,
									  const Key * rsa_pubkey);
static int		extract_gpg_rsa_seckey(const u_char * buf, int buf_len, Key * rsa_key);
static int		extract_gpg_curve25519_seckey(const u_char * buf, int buf_len, const Key * rsa_key,
											  u_char * d);
static int		extract_ephemeral_key(const u_char * msg, const u_char ** ephem_pk);
static int		extract_sym_key(const u_char * msg, const u_char * secret, const u_char * fp,
								u_char * sym_key);
static int		extract_gpg_one_pass_signature_packet(const u_char * buf, int buf_len, u_char * key_id);
static void		add_signature_trailer(SHA256_CTX * ctx, int data_len);
static int		process_data_signature_packet(const u_char * dec_buf, int buf_len, SHA256_CTX * sig_ctx,
	   										  const u_char * rsa_key_id);
static int		process_enc_data_hdr(SHA_CTX * sha_ctx, EVP_CIPHER_CTX * aes_ctx, FILE * infile,
									 u_char * output, u_char * rsa_key_id, char * fname, int * num_dec,
									 ssize_t * len, int * extra);
static int		process_enc_data(SHA_CTX * sha_ctx, SHA256_CTX * sig_ctx, EVP_CIPHER_CTX * aes_ctx,
								 const u_char * rsa_key_id, FILE * infile, FILE * outfile, u_char * output,
								 int offset, ssize_t len, int extra);

//  GPG packet generation funcs
static void		generate_gpg_public_key_packet(const Key * ssh_key, gpg_message * msg);
static void		generate_gpg_curve25519_subkey_packet(const u_char * pub_key, size_t pk_len, gpg_message * msg);
static void		generate_gpg_user_id_packet(const char * user_id, gpg_message * msg);
static void		populate_signature_header(struct sshbuf * body, int sig_class, gpg_tag pubkey_tag);
static void		generate_gpg_pk_uid_signature_packet(const gpg_message * pubkey_pkt, const gpg_message * uid_pkt,
						                             const Key * key, int sig_class,
													 const u_char * key_id, gpg_message * msg);
static void		generate_gpg_trust_packet(gpg_message * msg);
static int		generate_gpg_pkesk_packet(const gpg_public_key * key, u_char * sym_key_frame, int frame_len,
										  gpg_message * msg);
static void		generate_gpg_one_pass_signature_packet(const u_char * key_id, gpg_message * ops_pkt);
static int		generate_gpg_literal_data_packet(const char * fname, size_t file_len, time_t mod_time,
												 u_char * data_pkt_hdr);
static void		generate_gpg_data_signature_packet(const Key * rsa_key, const u_char * key_id,
										   		   gpg_message * sig_pkt);
static int		finalize_gpg_data_signature_packet(SHA256_CTX * sig_ctx, Key * rsa_key, gpg_message * sig_pkt);
static int		write_gpg_mdc_packet(FILE * outfile, SHA_CTX * sha_ctx, EVP_CIPHER_CTX * aes_ctx);

//  GPG packet retrieval funcs
static gpg_message * get_pub_key_packet(FILE * infile);
static gpg_message * get_curve25519_key_packet(FILE * infile);
static int		get_gpg_pkesk_packet(FILE * infile, const char * key_id, u_char * msg, gpg_tag * next_tag,
									 int * next_len);

//  GPG file manipulation funcs
static FILE *	open_rsa_seckey_file(const char * seckey_dir, const char * mode, const Key * ssh_key);
static FILE *	open_curve25519_seckey_file(const char * seckey_dir, const char * mode, const u_char * q,
											int q_len);
static FILE *	open_encrypted_output_file(const char * fname, char * enc_fname);
static FILE *	open_decrypted_output_file(const char * fname, char * dec_fname);
static int		write_encrypted_data_file(FILE * infile, const char * fname, const u_char * sym_key,
	   									  Key * rsa_key, const u_char * rsa_key_fp, FILE * outfile);
static int		get_public_keys(const char * login, Key * rsa_key, u_char * rsa_fp, u_char * key,
							    size_t * key_len, u_char * fp);
static int		get_secret_signing_key(Key * rsa_key);
static int		get_secret_encryption_key(const gpg_public_key * pub_keys, u_char * sec_key);
static int		read_pubkey_file(const char * login, Key * rsa_key, u_char * rsa_fp,
								 u_char * cv25519_key, size_t * cv25519_key_len, u_char * cv25519_fp,
								 char * uid);

//  GPG trustdb file funcs
static int		write_trustdb_htbl(FILE * tdb_file, const u_char * key, int key_len);
static void		generate_gpg_trustdb_version(u_char * rec);
static void		generate_gpg_trustdb_trust(u_char * rec, const u_char * key, int key_len, int next_rec);
static void		generate_gpg_trustdb_valid(u_char * rec, const char * uid);
static int		write_trustdb_file(const char * ssh_dir, const u_char * key, size_t key_len, const char * uid);

//  GPG key file generation funcs
static int		copy_ssh_key_file(const char * ssh_dir, const char * ext);
static int		copy_ssh_key_files(const char * ssh_dir);
static int		load_ssh_private_key(const char * ssh_key_file, const char * prompt, Key ** key);
static int		retrieve_ssh_private_key(const char * ssh_dir, const char * prompt, Key ** key);
static int		retrieve_ssh_public_key(const char * ssh_dir, char ** comment);
static int		retrieve_ssh_key(const char * const ssh_dir, Key ** key, char ** comment);
static int		write_public_key_file(FILE * pub_file, const Key * ssh_key, const u_char * pub_subkey,
							          const char * uid, u_char * key_fp, u_char * subkey_fp);
static int		write_secret_key_files(const char * ssh_dir, const Key * ssh_key, const u_char * q,
									   int q_len, const u_char * d, int d_len, const char * passphrase);
static int		write_rsa_key_to_pubkey(FILE * outfile, const Key * rsa_key, const u_char * fp,
										const char * uid);
static int		write_key_to_pubkey(FILE * outfile, const char * key_name, const u_char * pub_key, int len,
									const u_char * fp, const char * uid);
static int		write_pubkey_file(const char * login, Key * rsa_key, const u_char * key_fp,
								  const u_char * subkey,const u_char * subkey_fp,
								  const char * uid);
static int		generate_iron_keys(const char * const ssh_dir, const char * const login);

//  Recipient list funcs
static int		get_recipients(const gpg_public_key ** recip_list);
static const gpg_public_key * get_recipient_keys(const char * login);
static const gpg_public_key * get_recipient_keys_by_key_id(const char * key_id);


//================================================================================
//  Utility funcs
//================================================================================

/**
 *  Initialize the needful.
 *
 */
static int
initialize(void)
{
	int retval = 0;
	if (!inited) {
#ifdef WITH_OPENSSL
		OpenSSL_add_all_algorithms();
#endif
		if (sodium_init() == -1) {
			retval = -1;
			fatal("Couldn't initialize sodium library");
		}

		struct passwd * user_pw = getpwuid(getuid());
		if (user_pw == NULL) {
			retval = -1;
			fatal("Unable to determine current user's login\n");
		} else {
			user_login = xstrdup(user_pw->pw_name);
		}
		inited = 1;
	}

	gpg_now = time(NULL);
	return retval;
}

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
hex2str(const u_char * hex, int hex_len, char * str)
{
	char * ptr = str;
	const u_char * hptr = hex;

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
 *  If the string is too long to fit into hex, returns error.
 *
 *  @param str String of ASCII hex
 *  @param hex Place to write byte array. Should point to strlen(str) / 2 bytes
 *  @param hex_len Size of hex
 *  @return int Num bytes in hex, negative number if error
 */
static int
str2hex(const char * str, u_char * hex, int hex_len)
{
	int retval = -1;
	const char * ptr = str;
	u_char * hptr = hex;
	*hptr = '\0';

	if ((strlen(str) % 2) == 0) {
		int ct = 0;
		while (*ptr && ct < hex_len) {
			unsigned int t;
			if (sscanf(ptr, "%2x", &t) != 1) {
				break;
			}
			ptr += 2;
			*(hptr++) = t;
			ct++;
		}
		if (*ptr == '\0') {
			retval = hptr - hex;
		}
	}
	return retval;
}

/**
 *  Write a four-byte integer into a byte array.
 *
 *  @param val Integer
 *  @param buf Place to write val (at least 4 bytes)
 */
static void
int_to_buf(int val, u_char * buf)
{
	buf[0] = (u_char) (val >> 24);
	buf[1] = (u_char) (val >> 16);
	buf[2] = (u_char) (val >> 8);
	buf[3] = (u_char) val;
}

/**
 *  Convert four bytes from an array into an integer.
 *
 *  @param val buf array from which to read
 *  @return int extracted integer 
 */
static u_int32_t
buf_to_int(const u_char * buf)
{
	unsigned int len = 0;
	for (int i = 0; i < 4; i++) {
		len = (len << 8) + buf[i];
	}

	return len;
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
		u_char tmp[2 * GPG_MAX_KEY_SIZE];		//  Leave plenty of room
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
put_num_sexpr(struct sshbuf * buf, const u_char * bstr, int bstr_len)
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
 *  @param ssh_dir Place to write path (at least PATH_MAX chars)
 */
static void
populate_ssh_dir(const char * const login, char * ssh_dir)
{
	struct passwd * pw = getpwnam(login);
	if (pw != NULL) {
		snprintf(ssh_dir, PATH_MAX, "%s/.ssh/", pw->pw_dir);
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
	static char curr_ssh_dir[PATH_MAX] = { 0 };

	if (strcmp(login, user_login) == 0) {
		if (!(*curr_ssh_dir)) {
			populate_ssh_dir(login, curr_ssh_dir);
		}
		return curr_ssh_dir;
	}
	else {
		static char ssh_dir[PATH_MAX];
		populate_ssh_dir(login, ssh_dir);
		return ssh_dir;
	}
}

/**
 *  Check whether the ssh directory contains a private key subdir.
 *
 *  Looks in the specified path for a private-keys-v1.d subdirectory.
 *
 *  @param ssh_dir Path to the user's .ssh directory (usually under ~<login>
 *  @return char * Path of private key subdir (at least PATH_MAX chars). Caller should free
 */
static char *
check_seckey_dir(const char * ssh_dir)
{
	char dir_name[PATH_MAX];
	char * name_ptr = NULL;

	int len = snprintf(dir_name, PATH_MAX, "%s%s/", ssh_dir, GPG_SECKEY_SUBDIR);
	if (len < (int) sizeof(dir_name)) {
		if (mkdir(dir_name, 0700) == 0 || errno == EEXIST) {
			name_ptr = xstrdup(dir_name);
		}
	}

	return name_ptr;
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
hashcrypt(SHA_CTX * mdc_ctx, SHA256_CTX * sig_ctx, EVP_CIPHER_CTX * aes_ctx, const u_char * input,
	   	  int size, u_char * output)
{
	int num_written = -1;
	SHA1_Update(mdc_ctx, input, size);
	if (sig_ctx != NULL) {
		SHA256_Update(sig_ctx, input, size);
	}
	EVP_EncryptUpdate(aes_ctx, output, &num_written, input, size);
	return num_written;
}

/**
 *  Swap order of bytes in one byte array into a second array.
 *
 *  @param src Input byte array
 *  @param dst Place to write reversed byte array (at least len bytes)
 *  @param len Num bytes in src
 */
static void
reverse_byte_array(const u_char * src, u_char * dst, unsigned int len) {
	for (unsigned int i = 0; i < len; i++) {
		dst[i] = src[len - 1 - i];
	}
}

/**
 *  Swap order of bytes in a byte array in place
 *
 *  @param arr Byte array
 *  @param len Num bytes in arr
 */
static void
reverse_byte_array_in_place(u_char * arr, unsigned int len) {
	for (unsigned int ct = 0; ct < len / 2; ct++) {
		unsigned int ct2 = len - 1 - ct;
		u_char tmp = arr[ct];
		arr[ct]  = arr[ct2];
		arr[ct2] = tmp;
	}
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
clamp_and_reverse_seckey(u_char * sk)
{
	//  "Clamping" - Zero lowest three bits and highest bit of secret key, set next-to-highest bit. But
	//  libsodium/nacl represents the components little-endian (least signficant byte first).
	sk[crypto_box_SECRETKEYBYTES - 1] &= 0x7f;
	sk[crypto_box_SECRETKEYBYTES - 1] |= 0x40;
	sk[0] &= 0xf8;
	reverse_byte_array_in_place(sk, crypto_box_SECRETKEYBYTES);
}

/**
 *  Calculate SHA1 hash of sshbuf contents.
 *
 *  @param buf Buffer to hash
 *  @param hash Place to write computed hash - at least SHA_DIGEST_LENGTH bytes
 */
static void
compute_gpg_sha1_hash_sshbuf(const struct sshbuf * buf, u_char * hash)
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
compute_gpg_sha1_hash_chars(const u_char * bstr, int bstr_len, u_char * hash)
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
static int
generate_gpg_passphrase_from_rsa(const Key * rsa_key, char * passphrase)
{
	static int    cached_len = -1;
	static u_char cached_params[GPG_MAX_KEY_SIZE * 2];
	static char   cached_passphrase[PPHRASE_LEN];

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
			const char * ssh_dir = get_user_ssh_dir(user_login);
			if (ssh_dir != NULL) {
				int rv = retrieve_ssh_private_key(ssh_dir, "To decrypt file, enter passphrase for SSH key: ", &key);
				if (rv != 0) {
					error("Unable to retrieve SSH key: %s", ssh_err(rv));
					retval = -2;
					key = NULL;
				}
			} else {
				error("Unable to retrieve SSH key - no .ssh dir for login %s", user_login);
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
		u_int32_t len = buf_to_int(sptr);
		sptr += 4 + len;
		len = buf_to_int(sptr);
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
static void
compute_gpg_key_fingerprint(const gpg_message * pubkey_pkt, u_char * key_fp)
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
compute_rsa_signature(const u_char * digest, size_t digest_len, const Key * key)
{

	size_t rsa_len = RSA_size(key->rsa);
	unsigned int len;
	u_char * tmp_sig = malloc(rsa_len);

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
static struct sshbuf *
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
encrypt_gpg_key_frame(const u_char * sym_key_frame, int frame_len, const u_char * key,
					  u_char * enc_frame)
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
		const u_char * tmp_ptr = sshbuf_ptr(msg->data);
		int num_written = fwrite(tmp_ptr, sizeof(u_char), msg->len, outfile);
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
	u_char buf[GPG_NF_LEN_LONG];

	//  Read first byte of length to determine how many additional bytes there might be.
	if (fread(buf, 1, 1, infile) == 1) {
		u_char len_octet = buf[0];
		if (len_octet < GPG_NF_LEN_THRESHOLD1) {
			*size = len_octet;
			retval = 0;
		} else if (len_octet < GPG_NF_LEN_THRESHOLD2) {
			if (fread(buf, 1, 1, infile) == 1) {
				*size = ((len_octet - GPG_NF_LEN_THRESHOLD1) << 8) + buf[0] + GPG_NF_LEN_THRESHOLD1;
				retval = 0;
			}
		} else if (len_octet == GPG_NF_LEN_THRESHOLD4) {
			if (fread(buf, 1, 4, infile) == 4) {
				*size = buf_to_int(buf);
				retval = 0;
			}
		} else {
			// Partial body length
			*size = 1 << (len_octet - GPG_NF_LEN_THRESHOLD2);
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
 *  NOTE: a length of GPG_OF_LENGTH_INDETERMINATE (-1) indicates that the caller must figure out the packet length
 *  by some other means (the number of bytes left before EOF, typically).
 *
 *  @param infile File to read
 *  @param len_type Indicator of how long size is
 *  @param size Size read from file
 *  @return int 0 if successful, negative number if error
 */
static int
get_size_old_format(FILE * infile, u_char len_type, ssize_t * size)
{
	int retval = -1;
	u_char buf[GPG_OF_LEN_LONG];
	int num_octets;

	if (len_type <= GPG_TAG_OF_LENTYPE_MASK) {	//  Value is only supposed to be two bits
		switch (len_type) {
			case 0: num_octets = GPG_OF_LEN_SHORT; break;
			case 1: num_octets = GPG_OF_LEN_MEDIUM; break;
			case 2: num_octets = GPG_OF_LEN_LONG; break;
			case 3: num_octets = GPG_OF_LEN_INDETERMINATE; break;
		}

		if (num_octets > 0) {
			int num_read = fread(buf, sizeof(u_char), num_octets, infile);
			if (num_read == num_octets) {
				*size = 0;
				for (int i = 0; i < num_octets; i++) {
					*size = (*size << 8) + buf[i];
				}
				retval = 0;
			}
		} else {
			*size = GPG_OF_LEN_INDETERMINATE;
			retval = 0;
		}
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
		u_char buf[4];
		if (fread(buf, 1, 1, infile) == 1) {
			u_char tag_byte = buf[0];

			if ((tag_byte & GPG_TAG_MARKER_BIT) == GPG_TAG_MARKER_BIT) {
				int new_format = tag_byte & GPG_TAG_FORMAT_BIT;

				if (new_format) {
					*tag = (gpg_tag) (tag_byte & GPG_TAG_NF_MASK);
					retval = get_size_new_format(infile, size);

				} else {
					*tag = (gpg_tag) ((tag_byte & GPG_TAG_OF_MASK) >> GPG_TAG_OF_SHIFT);
					retval = get_size_old_format(infile, (tag_byte & GPG_TAG_OF_LENTYPE_MASK), size);
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
extract_size_new_format(const u_char * buf, ssize_t * size)
{
	int retval = -1;
	u_char len_octet = buf[0];
	if (len_octet < GPG_NF_LEN_THRESHOLD1) {
		*size = len_octet;
		retval = GPG_NF_LEN_SHORT;
	} else if (len_octet < GPG_NF_LEN_THRESHOLD2) {
		*size = ((len_octet - GPG_NF_LEN_THRESHOLD1) << 8) + buf[1] + GPG_NF_LEN_THRESHOLD1;
		retval = GPG_NF_LEN_MEDIUM;
	} else if (len_octet == GPG_NF_LEN_THRESHOLD4) {
		*size = 0;
		for (int i = 1; i < GPG_NF_LEN_LONG; i++) {
			*size = (*size << 8) + buf[i];
		}
		retval = GPG_NF_LEN_LONG;
	} else {
		// Partial body length
		*size = 1 << (len_octet - GPG_NF_LEN_THRESHOLD2);
		retval = GPG_NF_LEN_PARTIAL;
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
extract_size_old_format(const u_char * buf, u_char len_type, ssize_t * size)
{
	int retval = -1;
	int num_octets;

	if (len_type <= GPG_TAG_OF_LENTYPE_MASK) {
		switch (len_type) {
			case 0: num_octets = GPG_OF_LEN_SHORT; break;
			case 1: num_octets = GPG_OF_LEN_MEDIUM; break;
			case 2: num_octets = GPG_OF_LEN_LONG; break;
			case 3: num_octets = GPG_OF_LEN_INDETERMINATE; break;
		}

		if (num_octets > 0) {
			*size = 0;
			for (int i = 0; i < num_octets; i++) {
				*size = (*size << 8) + buf[i];
			}
			retval = num_octets;
		} else {
			*size = GPG_OF_LEN_INDETERMINATE;
			retval = 0;
		}
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
extract_tag_and_size(const u_char * buf, gpg_tag * tag, ssize_t * size)
{
	int retval = -2;

	if (tag != NULL && size != NULL) {
		u_char tag_byte = buf[0];

		if ((tag_byte & GPG_TAG_MARKER_BIT) == GPG_TAG_MARKER_BIT) {
			int new_format = tag_byte & GPG_TAG_FORMAT_BIT;

			if (new_format) {
				*tag = (gpg_tag) (tag_byte & GPG_TAG_NF_MASK);
				retval = extract_size_new_format(buf + 1, size);

			} else {
				*tag = (gpg_tag) ((tag_byte & GPG_TAG_OF_MASK) >> GPG_TAG_OF_SHIFT);
				retval = extract_size_old_format(buf + 1, (tag_byte & GPG_TAG_OF_LENTYPE_MASK), size);
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
 *  @return int Num bytes written to buf, negative number if error
 */
static int
generate_tag_and_size(gpg_tag tag, ssize_t size, u_char * buf)
{
	int len = -1;

	if ((int) tag <= GPG_OF_TAG_LIMIT) {
		//  Tag small enough to fit into an old-format tag octet and length.
		buf[0] = GPG_TAG_MARKER_BIT | (tag << GPG_TAG_OF_SHIFT);

		if (size < 0) {
			buf[0] |= GPG_OF_LENTYPE_INDETERMINATE;
			len = 1;		// Only tag byte - no length bytes
		} else if (size <= 0xff) {
			buf[0] |= GPG_OF_LENTYPE_SHORT;
			buf[1] = (u_char) size;
			len = GPG_OF_LEN_SHORT + 1;
		} else if (size <= 0xffff) {
			buf[0] |= GPG_OF_LENTYPE_MEDIUM;
			buf [1] = size >> 8;
			buf[2] = size;
			len = GPG_OF_LEN_MEDIUM + 1;
		} else if (size <= 0xffffffff) {
			buf[0] |= GPG_OF_LENTYPE_LONG;
			buf[1] = size >> 24;
			buf[2] = size >> 16;
			buf[3] = size >> 8;
			buf[4] = size;
			len = GPG_OF_LEN_LONG + 1;
		}
	} else if ((int) tag <= GPG_NF_TAG_LIMIT) {
		//  Use a new-format tag octet and length.
		buf[0] = GPG_TAG_MARKER_BIT | GPG_TAG_FORMAT_BIT | tag;

		if (size < GPG_NF_LEN_THRESHOLD1) {
			buf[1] = size;
			len = GPG_NF_LEN_SHORT + 1;
		} else if (size < GPG_NF_LEN_LIMIT_MEDIUM) {
			buf[1] = ((size - GPG_NF_LEN_THRESHOLD1) >> 8) + GPG_NF_LEN_THRESHOLD1;
			buf[2] = (size - GPG_NF_LEN_THRESHOLD1);
			len = GPG_NF_LEN_MEDIUM + 1;
		} else if (size <= 0xffffffff) {
			buf[1] = GPG_NF_LEN_THRESHOLD4;
			buf[2] = size >> 24;
			buf[3] = size >> 16;
			buf[4] = size >> 8;
			buf[5] = size;
			len = GPG_NF_LEN_LONG + 1;
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
generate_gpg_rsa_pub_parms(const Key * ssh_key)
{
	struct sshbuf * pub_parms = sshbuf_new();
	u_char tmp[512];
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
 *  Write a parenthesize S-expression into buffer.
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
	put_num_sexpr(buf, tmp, len);
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
		put_parm_in_sexpr(sec_parms, 'p', ssh_key->rsa->q);	// The p-q swapperoo
		put_parm_in_sexpr(sec_parms, 'q', ssh_key->rsa->p);	// The p-q swapperoo, part 2
		put_parm_in_sexpr(sec_parms, 'u', ssh_key->rsa->iqmp);
	}

	return sec_parms;
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
static struct sshbuf *
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
		compute_gpg_sha1_hash_sshbuf(hash_str, hash);

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
 *  Generate GPG keygrip for RSA key.
 *
 *  The GPG keygrip is a shortened representation (i.e. hash) of the parameters of the public key. The hash
 *  is just SHA1. The RSA keygrip is so much simpler than the curve25519 one - an RSA keygrip is just a SHA1
 *  hash of the public key parameter n.
 *
 *  @param key RSA key (only needs public params populated)
 *  @param grip Place to write keygrip. At least SHA_DIGEST_LENGTH bytes.
 */
static void
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

	compute_gpg_sha1_hash_chars(tmp_ptr, n_len, grip);
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
generate_gpg_curve25519_pub_parms(const u_char * q, int q_len)
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
generate_gpg_curve25519_sec_parms(const u_char * d, int d_len)
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
generate_gpg_curve25519_seckey(const u_char * q, int q_len, const u_char * d, int d_len,
		const u_char * passphrase)
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
 *  					 AES_WRAP_BLOCK_SIZE bytes
 *  @return int number of bytes in generated frame
 */
static int
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
generate_curve25519_shared_secret(const u_char * sec_key, const u_char * pub_key,
								  u_char * secret)
{
	u_char tseckey[crypto_box_SECRETKEYBYTES];
	reverse_byte_array(sec_key, tseckey, crypto_box_SECRETKEYBYTES);
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
 *  @param mdc_ctx SHA1 hash to update with input file data
 *  @param sig_ctx SHA256 hash to update with input file data
 *  @param aes_ctx AES cipher to use to encrypt input file data
 *  @return int Num bytes read from input file
 */
static int
encrypt_input_file(FILE * infile, FILE * outfile, SHA_CTX * mdc_ctx, SHA256_CTX * sig_ctx, EVP_CIPHER_CTX * aes_ctx)
{
	u_char * output = malloc(DECRYPT_CHUNK_SIZE + 2 * AES_BLOCK_SIZE);
	u_char * input = malloc(DECRYPT_CHUNK_SIZE);
	int             num_written;

	//  Now just read blocks of the input file, hash them, encrypt them, and output the encrypted data.
	int total_read = 0;
	int num_read = fread(input, 1, DECRYPT_CHUNK_SIZE, infile);
	while (num_read > 0) {
		total_read += num_read;
		num_written = hashcrypt(mdc_ctx, sig_ctx, aes_ctx, input, num_read, output);
		if (num_written < 0 || (int) fwrite(output, 1, num_written, outfile) != num_written) {
			total_read = -1;
			break;
		}
		num_read = fread(input, 1, DECRYPT_CHUNK_SIZE, infile);
	}

	free(output);
	free(input);
	return total_read;
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
#define MIN_PUBKEY_PKT_LEN 14		//  version, 4-byte timestamp, algo, 2 2-byte MPI lengths, 2 2-byte MPIs

static int
extract_gpg_rsa_pubkey(const struct sshbuf * buf, Key * rsa_key)
{
	int retval = -1;
	const u_char * ptr = sshbuf_ptr(buf);
	int len = sshbuf_len(buf);
	if (len >= MIN_PUBKEY_PKT_LEN) {
		ptr += 5;					//  Skip version, 4-byte timestamp
		if (*ptr == GPG_PKALGO_RSA_ES) {	//  Make sure the algorithm is what we expect
			ptr++;
			int key_len = (*ptr << 8) + *(ptr + 1);
			ptr += 2;
			key_len = (key_len + 7) / 8;	//  Convert from bites to bytes
			if (key_len <= GPG_MAX_KEY_SIZE) {
				rsa_key->rsa->n = BN_new();
				BN_bin2bn(ptr, key_len, rsa_key->rsa->n);
				ptr += key_len;
				//  Now grab the e value (another MPI)
				key_len = (*ptr << 8) + *(ptr + 1);
				ptr += 2;
				key_len = (key_len + 7) / 8;	//  Convert from bites to bytes
				rsa_key->rsa->e = BN_new();
				BN_bin2bn(ptr, key_len, rsa_key->rsa->e);
				retval = 0;
			}
		}
	}

	return retval;
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
	char passphrase[PPHRASE_LEN];

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
static int
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
static int
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
extract_ephemeral_key(const u_char * msg, const u_char ** ephem_pk)
{
	int retval = -1;
	const u_char * msg_ptr = msg;
	int epk_len = (*msg_ptr << 8) + *(msg_ptr + 1);
	epk_len = (epk_len + 7) / 8;		//  Convert from bits to bytes
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
static int
extract_sym_key(const u_char * msg, const u_char * secret, const u_char * fp,
				u_char * sym_key)
{
	int retval = -1;
	u_char kek[AES256_KEY_BYTES];
	u_char frame[AES256_KEY_BYTES + AES_WRAP_BLOCK_SIZE];

	generate_gpg_kek(fp, secret, kek);
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

//  The OPS packet has a fixed length - one byte each for the version, sig class, hash algo, PK
//  algo, and last flag, and 8 bytes for the key ID.  Total of 13 bytes.
#define ONE_PASS_SIG_LEN	13

/**
 *  Process One Pass Signature (OPS) packet
 *
 *  Mostly checks to make sure the fields are what we expect, but does extract the signer's key ID.
 *
 *  @param buf byte array from which to extract packet
 *  @param buf_len num bytes in buf
 *  @param key_id place to write key_id (at least GPG_KEY_ID_LEN bytes)
 *  @return number bytes consumed from buf, or negative number if error
 */
static int
extract_gpg_one_pass_signature_packet(const u_char * buf, int buf_len, u_char * key_id)
{
	if (buf_len < ONE_PASS_SIG_LEN) return -1;

	const u_char * ptr = buf;
	if (*(ptr++) != GPG_OPS_VERSION) return -2;
	if (*(ptr++) != GPG_SIGCLASS_BINARY_DOC) return -3;
	if (*(ptr++) != GPG_HASHALGO_SHA256) return -4;
	if (*(ptr++) != GPG_PKALGO_RSA_ES) return -5;
	memcpy(key_id, ptr, GPG_KEY_ID_LEN);
	ptr += GPG_KEY_ID_LEN;
	if (*(ptr++) != 1) return -6;			//  Last OPS flag should always be set

	return ONE_PASS_SIG_LEN;
}

/**
 *  Adds the little "trailer" sequence into signature hash.
 *
 *  Assumes that a hash has been computed on the data being signed. GPG adds this little 6 byte trailer into
 *  the hash before finalizing it. The length here is the number of bytes in the signature packet from the
 *  start of the packet (not including the tag/length header) through the end of the hashed data subpackets.
 *
 *  @param ctx SHA256 hash to update
 *  @param len number of bytes in start of signature packet, through the hashed data subpackets
 */
static void
add_signature_trailer(SHA256_CTX * ctx, int len)
{
	u_char trailer[6];
	trailer[0] = GPG_SIG_VERSION;
	trailer[1] = 0xff;
	int_to_buf(len, trailer + 2);
	SHA256_Update(ctx, trailer, 6);
}

/**
 *  Extract data signature packet from buffer, verify.
 *
 *  Ensure that the signature packet is as expected, and if so, try to validate the signature. If we can't
 *  find the public RSA signing key, output a warning. If we can, validate that the computed signature
 *  matches the one in the signature packet. If not, return an error.
 *
 *  @param dec_buf array of bytes holding decrypted data
 *  @param buf_len num bytes in dec_buf
 *  @param sig_ctx SHA256 hash that has been computed over the file data
 *  @param rsa_key_id key ID from OPS packet
 *  @return 0 if signature validates successfully, negative number if errors
 */
static int
process_data_signature_packet(const u_char * dec_buf, int buf_len, SHA256_CTX * sig_ctx, const u_char * rsa_key_id)
{
	gpg_tag tag;
	size_t len;
	int sig_hdr_len = extract_tag_and_size(dec_buf, &tag, &len);
	if (sig_hdr_len < 0 || buf_len < (int) len) return -1;
	if (tag != GPG_TAG_SIGNATURE) return -2;

	const u_char * dptr = dec_buf + sig_hdr_len;
	if (*(dptr++) != GPG_SIG_VERSION) return -3;
	if (*(dptr++) != GPG_SIGCLASS_BINARY_DOC) return -4;
	if (*(dptr++) != GPG_PKALGO_RSA_ES) return -5;
	if (*(dptr++) != GPG_HASHALGO_SHA256) return -6;
	int hashed_len = (*dptr << 8) + *(dptr + 1);
	dptr += 2;
	if (hashed_len != 6 || *(dptr++) != 5) return -7;
	if (*(dptr++) != GPG_SIG_SUBPKT_SIGNATURE_CREATION_TIME) return -8;
	u_int32_t create_ts = buf_to_int(dptr);
	dptr += 4;  //  Skip creation time subpacket

	//  Hash includes all of the signature packet after the tag/len header through the end of the hashed
	//  subpackets.
	hashed_len = dptr - dec_buf - sig_hdr_len;
	SHA256_Update(sig_ctx, dec_buf + sig_hdr_len, hashed_len);
	add_signature_trailer(sig_ctx, hashed_len);
	u_char hash[SHA256_DIGEST_LENGTH];
	SHA256_Final(hash, sig_ctx);

	//  Finish verifying unhashed subpackets.
	int unhashed_len = (*dptr << 8) + *(dptr + 1);
	dptr += 2;
	if (unhashed_len != GPG_KEY_ID_LEN + 2 || *(dptr++) != GPG_KEY_ID_LEN + 1) return -9;
	if (*(dptr++) != GPG_SIG_SUBPKT_ISSUER) return -10;

	u_char key_id[GPG_KEY_ID_LEN];
	memcpy(key_id, dptr, GPG_KEY_ID_LEN);
	dptr += GPG_KEY_ID_LEN;

	if (memcmp(rsa_key_id, key_id, GPG_KEY_ID_LEN) != 0) return -11;

	//  Now we are to the actual signature. Attempt to find the public RSA signing key corresponding to
	//  the key ID from the OPS/Signature packets, sign the hash, and compare to the signature in the packet.
	char hex_id[2 * GPG_KEY_ID_LEN + 1];
	hex2str(key_id, GPG_KEY_ID_LEN, hex_id);

	//  Quick check of the first two bytes of the hash.
	if (*dptr != hash[0] || *(dptr + 1) != hash[1]) return -12;
	dptr += 2;

	const gpg_public_key * signer_keys = get_recipient_keys_by_key_id(key_id);
	if (signer_keys != NULL) {
		int sig_len = (*dptr << 8) + *(dptr + 1);	//  Size in bits
		dptr += 2;
		sig_len = (sig_len + 7) / 8;			//  Convert to bytes

		if (RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, dptr, sig_len, signer_keys->rsa_key.rsa) != 1) {
			error("ERROR: message was signed by user %s, key ID %s,\n       but signature is not correct.",
				  signer_keys->login, hex_id);
			return -13;
		} else {
			logit("Message was signed by user %s, key ID %s.", signer_keys->login, hex_id);
		}
	} else {
		logit("WARNING: unable to identify owner of key ID %s - unable to verify signature.", hex_id);
	}

	return len + sig_hdr_len;
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
 *  @param dec_buf Place to store decrypted data (at least 528 bytes)
 *  @param fname Place to store name of the file that was encrypted (at least PATH_MAX bytes)
 *  @param num_dec Place to store number of bytes decrypted
 *  @param len Place to store remaining size of encrypted data to process
 *  @param extra Place to store number of bytes of trailing MDC packet that have already been read
 *  @return int Num bytes written to dec_buf array, negative number if error
 */
static int
process_enc_data_hdr(SHA_CTX * mdc_ctx, EVP_CIPHER_CTX * aes_ctx, FILE * infile, u_char * dec_buf,
	   				 u_char * rsa_key_id, char * fname, int * num_dec, ssize_t * len, int * extra)
{
//  After the header for the SEIPD packet and the one byte version number, there should be encrypted
//  data. The start of this data has 16 bytes of random data, the last two bytes of that data repeated,
//  the header of the literal data packet (at least two bytes), a byte for the data format, a byte for
//  the file name length, the file name (at least one byte), and a four byte timestamp.
#define MIN_ENC_DATA_HDR_SIZE	27

	//  More than enough space to get through all the header stuff and into the encrypted file data.
	u_char input[DECRYPT_CHUNK_SIZE];
	size_t num_read = fread(input, 1, sizeof(input), infile);
	if (num_read < MIN_ENC_DATA_HDR_SIZE) {
		error("Input too short - cannot recover data.");
		return -1;
	}

	EVP_DecryptUpdate(aes_ctx, dec_buf, num_dec, input, num_read);
	if (*num_dec <= AES_BLOCK_SIZE + 2) {
		error("Decrypted input too short - cannot recover data.");
		return -2;
	}

	//  The first 16 bytes are random data, then the last two bytes of those 16 should be repeated.
	if (dec_buf[AES_BLOCK_SIZE] != dec_buf[AES_BLOCK_SIZE - 2] ||
			dec_buf[AES_BLOCK_SIZE + 1] != dec_buf[AES_BLOCK_SIZE - 1]) {
		error("Checksum error in header - cannot recover data.");
		return -3;
	}
	u_char * dptr = dec_buf + AES_BLOCK_SIZE + 2;

	gpg_tag tag = GPG_TAG_DO_NOT_USE;
	*len = 0;

	//  First up, we expect a One Pass Signature (OPS) packet.
	int tag_size_len = extract_tag_and_size(dptr, &tag, len);
	dptr += tag_size_len;
	int ops_len = extract_gpg_one_pass_signature_packet(dptr, *num_dec - (dptr - dec_buf), rsa_key_id);
	if (tag != GPG_TAG_ONE_PASS_SIGNATURE || ops_len < 0 || ops_len != *len) {
		error("Input file missing valid one pass signature.");
		return -4;
	}
	dptr += ops_len;

	tag_size_len = extract_tag_and_size(dptr, &tag, len);
	dptr += tag_size_len;
	if (tag != GPG_TAG_LITERAL_DATA || *(dptr++) != 'b') {	//	We always write literal data in "binary" format)
		error("Unexpected data at start of packet - cannot recover data.");
		return -4;
	}
	int fname_len = *(dptr++);
	memcpy(fname, dptr, fname_len);
	fname[fname_len] = '\0';
	dptr += fname_len;

	u_int32_t file_ts = buf_to_int(dptr);
	dptr += 4;

	*len -= fname_len + 1 /*format spec*/ + 1 /* fname len byte*/ + 4 /*timestamp*/;

	//  The rest of the encrypted data is the encrypted file data, followed by the signature and MDC packets.
	//  Figure out how much of the current decrypted buffer is file data - part of it might be MDC packet.
	//  *len contains the number of bytes left in the literal data packet
	//  *num_dec contains the number of bytes left in the decryption output buffer
	*num_dec -= (dptr - dec_buf);
	SHA1_Update(mdc_ctx, dec_buf, dptr - dec_buf);

	if (*len < *num_dec) {  // At least part of Sig/MDC packet in buffer
		*extra = *num_dec - *len;
		*num_dec = *len;
	} else {
		*extra = 0;
	}

	return dptr - dec_buf;
}

/**
 *  Read encrypted input, write decrypted output.
 *
 *  Read chunks from the file, decrypt them, and write the decrypted data to the output file until
 *  we have exhausted the literal data packet.
 *
 *  *** NOTE: until we have a way to retrieve the RSA key for a key ID, we can't verify the signature
 *  packet. But we do accumulate the hash as we go, in preparation.
 *
 *  @param mdc_ctx SHA1 hash of decrypted data
 *  @param aes_ctx AES cipher to decrypt data
 *  @param rsa_key_id ID of the key that signed the data while encrypting
 *  @param infile File from which to read encrypted data
 *  @param outfile File to which to write decrypted data
 *  @param output Place to store decrypted data (at least DECRYPT_CHUNK_SIZE + 2 * AES_BLOC_SIZE bytes)
 *  @param offset Offset into output buffer at which to start initially
 *  @param len Num bytes enc. data to process
 *  @param extra Num bytes of MDC packet already read
 *  @return int 0 if successful, negative number if error
 */
static int
process_enc_data(SHA_CTX * mdc_ctx, SHA256_CTX * sig_ctx, EVP_CIPHER_CTX * aes_ctx, const u_char * rsa_key_id,
				 FILE * infile, FILE * outfile, u_char * dec_buf, int offset, ssize_t len, int extra)
{
	int retval = 0;

	u_char input[DECRYPT_CHUNK_SIZE];
	int num_dec;
	int num_read;
	u_char * dptr = dec_buf + offset;

	//  If there was any Sig/MDC data in dec_buf when we enter, len would be zero. If len is not zero, we
	//  are OK to start overwriting the dec_buf.
	while (len > 0) {
		num_read = fread(input, 1, sizeof(input), infile);
		if (ferror(infile)) {
			error("Error reading input file.");
			retval = -1;
			break;
		}
		EVP_DecryptUpdate(aes_ctx, dec_buf, &num_dec, input, num_read);

		dptr = dec_buf;
		if (len < num_dec) {  // At least part of MDC packet in buffer
			extra = num_dec - len;
			dptr += len;
			num_dec = len;
		} else {
			extra = 0;
			dptr += num_dec;
		}

		if (fwrite(dec_buf, 1, num_dec, outfile) != (size_t) num_dec) {
			error("Error writing output file");
			retval = -1;
			break;
		}
		len -= num_dec;
		SHA1_Update(mdc_ctx, dec_buf, num_dec);
		SHA256_Update(sig_ctx, dec_buf, num_dec);
	}

	//  When we get to here, we should have written the entire decrypted data file, and dptr should
	//  point to the start of the Signature packet, if there was part of it in the last decrypted block.
	//  Read the rest of the Signature and MDC packets and validate them.
	if (retval == 0) {
		retval = -1;

		num_read = fread(input, 1, sizeof(input), infile);
		if (!ferror(infile)) {
			if (extra > 0) {
				memmove(dec_buf, dptr, extra);
				dptr = dec_buf + extra;
			}
			EVP_DecryptUpdate(aes_ctx, dptr, &num_dec, input, num_read);
			int last_dec;
			EVP_DecryptFinal_ex(aes_ctx, dptr + num_dec, &last_dec);
			num_dec += last_dec + extra;

			//  dec_buf should contain the signature packet followed by the MDC packet now.
			last_dec = process_data_signature_packet(dec_buf, num_dec, sig_ctx, rsa_key_id);
			if (last_dec > 0) {
				SHA1_Update(mdc_ctx, dec_buf, last_dec);
				dptr = dec_buf + last_dec;

				if ((num_dec - last_dec) == GPG_MDC_PKT_LEN) {
					SHA1_Update(mdc_ctx, dptr, 2);
					u_char digest[SHA_DIGEST_LENGTH];
					SHA1_Final(digest, mdc_ctx);

					if (memcmp(dptr + 2, digest, sizeof(digest)) == 0) {
						retval = 0;
					} else {
						error("Invalid Modification Detection Code - cannot recover data.");
					}
				} else {
					error("Length of input incorrect - cannot recover data.");
				}
			} else {
				error("Unable to validate signature (error %d) - cannot recover data.", last_dec);
			}
		} else {
			error("Error reading input file.");
		}
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
 *  @param msg Place to write packet. Caller should sshbuf_free msg->data
 */
static void
generate_gpg_public_key_packet(const Key * ssh_key, gpg_message * msg)
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
 *  @param msg Place to put generated packet. Caller should sshbuf_free msg->data
 */
static void
generate_gpg_curve25519_subkey_packet(const u_char * pub_key, size_t pk_len, gpg_message * msg)
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
	u_char * prefixed_pk = malloc(pk_len + 1);
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
 *  @param msg Place to write packet. Caller should sshbuf_free msg->data
 */
static void
generate_gpg_user_id_packet(const char * user_id, gpg_message * msg)
{
	msg->tag = GPG_TAG_USERID;
	msg->data = sshbuf_from(user_id, strlen(user_id));
	msg->len = sshbuf_len(msg->data);
}

/**
 *  Write the fixed info at the start of the signature packet body.
 *
 *  @param body Place to write body data
 *  @param sig_class Type of signature to generate
 *  @param pubkey_tag Tag from the public key or subkey packet preceding signature
 */
static void
populate_signature_header(struct sshbuf * body, int sig_class, gpg_tag pubkey_tag)
{
	sshbuf_put_u8(body, GPG_SIG_VERSION);
	sshbuf_put_u8(body, sig_class);
	sshbuf_put_u8(body, GPG_PKALGO_RSA_ES);
	sshbuf_put_u8(body, GPG_HASHALGO_SHA256);
	sshbuf_put_u16(body, 24);  		//  Length of hashed subpackets
	sshbuf_put_u8(body, 5);			//  Length of signature creation time subpacket
	sshbuf_put_u8(body, GPG_SIG_SUBPKT_SIGNATURE_CREATION_TIME);
	sshbuf_put_u32(body, gpg_now);
	sshbuf_put_u8(body, 5);			//  Length of key lifetime subpacket
	sshbuf_put_u8(body, GPG_SIG_SUBPKT_KEY_LIFETIME);
	sshbuf_put_u32(body, 0);			//  Does not expire
	sshbuf_put_u8(body, 5);			//  Length of preferred symmetric algorithm subpacket
	sshbuf_put_u8(body, GPG_SIG_SUBPKT_PREF_SYM_ALGO);
	sshbuf_put_u8(body, GPG_SKALGO_AES256);
	sshbuf_put_u8(body, GPG_SKALGO_AES192);
	sshbuf_put_u8(body, GPG_SKALGO_AES128);
	sshbuf_put_u8(body, 0);			//  No fourth preferred SK algorithm
	sshbuf_put_u8(body, 2);			//  Length of key flags subpacket
	sshbuf_put_u8(body, GPG_SIG_SUBPKT_KEY_FLAGS);
	if (pubkey_tag == GPG_TAG_PUBLIC_KEY) {
		sshbuf_put_u8(body, 0x03);		// Sign + certify
	} else if (pubkey_tag == GPG_TAG_PUBLIC_SUBKEY) {
		sshbuf_put_u8(body, 0x0c);		// encrypt
	} else {
		sshbuf_put_u8(body, 0x00);
	}
	sshbuf_put_u8(body, 2);			//  Length of features subpacket
	sshbuf_put_u8(body, GPG_SIG_SUBPKT_FEATURES);
	sshbuf_put_u8(body, 0x01);			// enabled MDC - integrity protection for encrypted data packets
}

/**
 *  Compute the hash that goes in the signature packet
 *
 *  The hash is over the pubkey packet, uid packet, and the start of the signature packet.
 *
 *  @param pubkey_pkt Already generated public key (or subkey) packet
 *  @param uid_pkt Already generated UID packet, or NULL if no UID packet (signing subkey, for example)
 *  @param sig_pkt First portion of the signature packet (everything that needs to be hashed)
 *  @param hash Place to write the hash (at least SHA256_DIGEST_LENGTH bytes)
 */
static void
compute_signature_hash(const gpg_message * pubkey_pkt, const gpg_message * uid_pkt, const gpg_message * sig_pkt,
					   u_char * hash)
{
	SHA256_CTX  ctx;
	SHA256_Init(&ctx);

	u_char buf[6];

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
		int_to_buf(uid_pkt->len, buf + 1);
		SHA256_Update(&ctx, buf, 5);
		SHA256_Update(&ctx, sshbuf_ptr(uid_pkt->data), sshbuf_len(uid_pkt->data));
	}

	/* Now add the first part of the signature packet, through the hashed data section. */
	SHA256_Update(&ctx, sshbuf_ptr(sig_pkt->data), sshbuf_len(sig_pkt->data));
	add_signature_trailer(&ctx, sshbuf_len(sig_pkt->data));
	SHA256_Final(hash, &ctx);
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
 *  @param msg Place to write generated packet. Caller should sshbuf_free msg->data
 */
static void
generate_gpg_pk_uid_signature_packet(const gpg_message * pubkey_pkt, const gpg_message * uid_pkt,
									 const Key * key, int sig_class, const u_char * key_id,
									 gpg_message * msg)
{
	msg->tag = GPG_TAG_SIGNATURE;
	msg->data = sshbuf_new();

	populate_signature_header(msg->data, sig_class, pubkey_pkt->tag);

	u_char hash[SHA256_DIGEST_LENGTH];
	compute_signature_hash(pubkey_pkt, uid_pkt, msg, hash);

	/* Add the unhashed subpackets to the signature packet now. Currently, just the issuer subpacket. */
	sshbuf_put_u16(msg->data, GPG_KEY_ID_LEN + 2);	//  Length of unhashed subpackets
	sshbuf_put_u8(msg->data, GPG_KEY_ID_LEN + 1);	//  Length of issuer subpacket
	sshbuf_put_u8(msg->data, GPG_SIG_SUBPKT_ISSUER);
	sshbuf_put(msg->data, key_id, GPG_KEY_ID_LEN);

	/* Tack on the first two bytes of the hash value, for error detection. */
	sshbuf_put_u8(msg->data, hash[0]);
	sshbuf_put_u8(msg->data, hash[1]);

	/* Now compute the RSA signature of the hash - m^d mod n, where m is the message (the hash), d is the
	 * private key, and n is the modulus. This MPI goes into the signature packet (with the normal two-octet
	 * length prefix).
	* */
	BIGNUM * sig = compute_rsa_signature(hash, SHA256_DIGEST_LENGTH, key);
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
generate_gpg_pkesk_packet(const gpg_public_key * key, u_char * sym_key_frame, int frame_len,
						  gpg_message * msg)
{
	int retval = -1;

	msg->tag = GPG_TAG_PKESK;
	msg->data = sshbuf_new();

	sshbuf_put_u8(msg->data, GPG_PKESK_VERSION);
	sshbuf_put(msg->data, key->fp + (GPG_KEY_FP_LEN - GPG_KEY_ID_LEN), GPG_KEY_ID_LEN);
	sshbuf_put_u8(msg->data, GPG_PKALGO_ECDH);		//  Algorithm used to encrypt symmetric key

	u_char secret[crypto_box_BEFORENMBYTES];
	u_char ephem_pk[crypto_box_PUBLICKEYBYTES + 1];
	generate_curve25519_ephem_shared_secret(key->key, ephem_pk + 1, secret);
	ephem_pk[0] = GPG_ECC_PUBKEY_PREFIX;			//  Indicates that it is on the X value, not the complete point

	u_char kek[AES128_KEY_BYTES];
	generate_gpg_kek(key->fp, secret, kek);

	//  We are going to encrypt the sym. key frame using AES128-WRAP. This requires that the frame be a multiple
	//  of the block size (8), which it is. The encryption will add one more block on the end of the encrypted
	//  data.
	//  Also leave an extra byte at the beginning to hold the encrypted frame length.
	u_char * enc_frame = malloc(frame_len + 2 * AES_WRAP_BLOCK_SIZE + 1);
	int enc_frame_len = encrypt_gpg_key_frame(sym_key_frame, frame_len, kek, enc_frame + 1);
	if (enc_frame_len > 0) {
		*enc_frame = (u_char) enc_frame_len;
		enc_frame_len++;

		//  Write the ephemeral PK first, prefixed with the two-byte length in bits.
		//  Then write the encrypted frame without a length prefix.
		sshbuf_put_u16(msg->data, crypto_box_PUBLICKEYBYTES * 8 + 7);
		sshbuf_put(msg->data, ephem_pk, sizeof(ephem_pk));
		sshbuf_put(msg->data, enc_frame, enc_frame_len);
		msg->len = sshbuf_len(msg->data);
		retval = 0;
	}

	return retval;
}

/**
 *  Generate a GPG One Pass Signature packet.
 *
 *  @param key_id ID of the RSA key that will be signing the following data.
 *  @param msg Place to write generated packet
 */
static void
generate_gpg_one_pass_signature_packet(const u_char * key_id, gpg_message * ops_pkt)
{
	ops_pkt->tag = GPG_TAG_ONE_PASS_SIGNATURE;
	ops_pkt->data = sshbuf_new();
	sshbuf_put_u8(ops_pkt->data, GPG_OPS_VERSION);
	sshbuf_put_u8(ops_pkt->data, GPG_SIGCLASS_BINARY_DOC);
	sshbuf_put_u8(ops_pkt->data, GPG_HASHALGO_SHA256);
	sshbuf_put_u8(ops_pkt->data, GPG_PKALGO_RSA_ES);
	sshbuf_put(ops_pkt->data, key_id, GPG_KEY_ID_LEN);
	sshbuf_put_u8(ops_pkt->data, 1);		//  Last flag - we always include just one signature
	ops_pkt->len = sshbuf_len(ops_pkt->data);
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
 *  @return int Num bytes in data_pkt_hdr, or negative number if error
 */
static int
generate_gpg_literal_data_packet(const char * fname, size_t file_len, time_t mod_time,
								 u_char * data_pkt_hdr)
{
	//  We only put the base file name into the packet - strip the path before doing anything with it.
	char * tmp_name = strdup(fname);
	char * base_name = basename(tmp_name);

	if (base_name == NULL || strlen(base_name) == 0 || strlen(base_name) > 0xff) {
		free(tmp_name);
		return -1;
	}

	//  Determine size of inner Literal Data Packet
	u_char literal_hdr[6];
	int data_len = file_len + 4 /*timestamp*/ + strlen(base_name) + 1 /*fname len*/ + 1 /*data fmt*/;
	int literal_hdr_len = generate_tag_and_size(GPG_TAG_LITERAL_DATA, data_len, literal_hdr);

	u_char * dptr = data_pkt_hdr;
	memcpy(dptr, literal_hdr, literal_hdr_len);
	dptr += literal_hdr_len;
	*(dptr++) = 'b';   				//  Indicates "binary" data, no CR-LF conversion
	*(dptr++) = strlen(base_name);	//  Precede name by its length, in one byte
	strcpy(dptr, base_name);
	dptr += strlen(base_name);
	int_to_buf(mod_time, dptr);
	dptr += 4;
	free(tmp_name);

	return dptr - data_pkt_hdr;
}

/**
 *  Generate a signature packet to sign literal data
 *
 *  Fills out the packet up to the first two bytes of the hash and the actual signature - those will be
 *  populated later.
 *
 *  @param rsa_key So we can compute how big the actual signature will be.
 *  @param key_id Of the signing key
 *  @param sig_pkt place to put the signature packet
 */
static void
generate_gpg_data_signature_packet(const Key * rsa_key, const u_char * key_id, gpg_message * sig_pkt)
{
	sig_pkt->tag = GPG_TAG_SIGNATURE;
	sig_pkt->data = sshbuf_new();
	sshbuf_put_u8(sig_pkt->data, GPG_SIG_VERSION);
	sshbuf_put_u8(sig_pkt->data, GPG_SIGCLASS_BINARY_DOC);
	sshbuf_put_u8(sig_pkt->data, GPG_PKALGO_RSA_ES);
	sshbuf_put_u8(sig_pkt->data, GPG_HASHALGO_SHA256);
	sshbuf_put_u16(sig_pkt->data, 6);				//  Length of hashed subpackets
	sshbuf_put_u8(sig_pkt->data, 5);				//  Length of signature creation time subpacket
	sshbuf_put_u8(sig_pkt->data, GPG_SIG_SUBPKT_SIGNATURE_CREATION_TIME);
	sshbuf_put_u32(sig_pkt->data, gpg_now);
	sshbuf_put_u16(sig_pkt->data, GPG_KEY_ID_LEN + 2);	//  Length of unhashed subpackets
	sshbuf_put_u8(sig_pkt->data, GPG_KEY_ID_LEN + 1);	//  Length of issuer subpacket
	sshbuf_put_u8(sig_pkt->data, GPG_SIG_SUBPKT_ISSUER);
	sshbuf_put(sig_pkt->data, key_id, GPG_KEY_ID_LEN);

	//  This is all we can fill in for now. The rest of the packet will be two bytes that are the first
	//  two bytes of the hash that is being signed, then the signature. The signature length is the same
	//  as the RSA key length. We will set the length to include that data now, but we will populate it
	//  later.
	size_t rsa_len = RSA_size(rsa_key->rsa);
	sig_pkt->len = sshbuf_len(sig_pkt->data) + 2 /* hash bytes */ + 2 /* MPI length */ + rsa_len;
}

/**
 *  Finish off the signature packet
 *
 *  Given the hash to this point, stuff in the trailer stuff, compute the hash, sign it, and put the data
 *  into the signature packet that was started by generate_gpg_data_signature_packet.
 *
 *  @param
 */
static int
finalize_gpg_data_signature_packet(SHA256_CTX * sig_ctx, Key * rsa_key, gpg_message * sig_pkt)
{
	int retval = -1;

	//  Determine the length of the signature packet through the hashed data section. The body starts
	//  with four octets (version, signature class, PK algorithm, and hash algorithm), then the hashed
	//  subpacket length.
	const u_char * ptr = sshbuf_ptr(sig_pkt->data) + 4;
	int len = (*ptr << 8) + *(ptr + 1);
	len += 6;		//  For the initial bytes, plus the two-byte hashed subpacket length

	SHA256_Update(sig_ctx, sshbuf_ptr(sig_pkt->data), len);
	add_signature_trailer(sig_ctx, len);

	u_char sig_hash[SHA256_DIGEST_LENGTH];
	SHA256_Final(sig_hash, sig_ctx);

	sshbuf_put_u8(sig_pkt->data, sig_hash[0]);
	sshbuf_put_u8(sig_pkt->data, sig_hash[1]);

	if (get_secret_signing_key(rsa_key) == 0) {
		BIGNUM * sig = compute_rsa_signature(sig_hash, SHA256_DIGEST_LENGTH, rsa_key);
		put_bignum(sig_pkt->data, sig);
		BN_clear_free(sig);
		if ((int)sshbuf_len(sig_pkt->data) == (int)sig_pkt->len) {
			retval = 0;
		} else {
			error("Internal error finalizing signature packet.");
		}
	}

	return retval;
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
	u_char input[SHA_DIGEST_LENGTH + 2];
	input[0] = 0xd3;		//  The formatted tag of the Modification Detection Code (MDC) packet
	input[1] = 0x14;		//  The length of the MDC packet

	SHA1_Update(sha_ctx, input, 2);
	SHA1_Final(input + 2, sha_ctx);

	u_char output[2 * AES_BLOCK_SIZE];
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
		u_char * key = malloc(len);
		if (fread(key, 1, len, infile) == (size_t) len) {
			msg = malloc(sizeof(gpg_message));
			msg->tag = tag;
			msg->len = len;
			msg->data = sshbuf_from(key, len);
		} else {
			error("Unable to read full public key packet from file.");
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
	u_char * subkey = NULL;

	do {
		get_tag_and_size(infile, &tag, &len);
		if (tag != GPG_TAG_PUBLIC_SUBKEY) {
			fseek(infile, len, SEEK_CUR);
		} else {
			subkey = malloc(len);
			if (fread(subkey, 1, len, infile) != (size_t) len) {
				error("Unable to read complete public subkey packet from file.");
				free(subkey);
				subkey = NULL;
				break;
			}
		}
	} while (!feof(infile) && tag != GPG_TAG_PUBLIC_SUBKEY);

#define GPG_SUBKEY_PK_ALGO_OFFSET 5		//  # bytes - 1 from start of packet body to the algorithm type

	if (tag == GPG_TAG_PUBLIC_SUBKEY && subkey != NULL) {
		//  Make sure it's a curve22519 subkey. Shouldn't be anything else in the file, but just make sure.
		if (subkey[GPG_SUBKEY_PK_ALGO_OFFSET] != GPG_PKALGO_ECDH ||
				memcmp(subkey + GPG_SUBKEY_PK_ALGO_OFFSET + 1, curve25519_oid, sizeof(curve25519_oid)) != 0) {
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
get_gpg_pkesk_packet(FILE * infile, const char * key_id, u_char * msg, gpg_tag * next_tag, int * next_len)
{
	int retval = IRON_ERR_NOT_FOR_USER;

	*next_tag = GPG_TAG_DO_NOT_USE;
	*next_len = -1;
	gpg_tag tag;
	size_t len;

	if (get_tag_and_size(infile, &tag, &len) != 0) {
		return IRON_ERR_NOT_ENCRYPTED;
	}

	while (tag == GPG_TAG_PKESK && !feof(infile)) {
		u_char pkt_start[GPG_KEY_ID_LEN + 1];
		if (fread(pkt_start, 1, sizeof(pkt_start), infile) == sizeof(pkt_start)) {
			size_t left_to_read = len - (GPG_KEY_ID_LEN + 1);
			if (*pkt_start != GPG_PKESK_VERSION) {
				retval = IRON_ERR_NOT_ENCRYPTED;
				break;
			} else if (memcmp(key_id, pkt_start + 1, GPG_KEY_ID_LEN) == 0) {
				if (fread(msg, 1, left_to_read, infile) == left_to_read) {
					retval = 0;
				} else {
					retval = IRON_ERR_NOT_ENCRYPTED;
					break;
				}
			} else {
				if (fseek(infile, left_to_read, SEEK_CUR) != 0) {
					retval = IRON_ERR_NOT_ENCRYPTED;
					break;
				}
			}
		} else {
			retval = IRON_ERR_NOT_ENCRYPTED;
			break;
		}

		if (get_tag_and_size(infile, &tag, &len) != 0) {
			retval = IRON_ERR_NOT_ENCRYPTED;
			break;
		}
	}

	if (retval == 0 && !feof(infile)) {
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
 *  @param mode Mode string to use for fopen (e.g. "r", "w+")
 *  @param rsa_key RSA key (only need public portion)
 *  @return FILE * File containing RSA secret key, opened in specified mode
 */
static FILE *
open_rsa_seckey_file(const char * seckey_dir, const char * mode, const Key * rsa_key)
{
	u_char keygrip[SHA_DIGEST_LENGTH];
	char hexgrip [2 * SHA_DIGEST_LENGTH + 1];

	generate_gpg_rsa_keygrip(rsa_key, keygrip);
	hex2str(keygrip, sizeof(keygrip), hexgrip);

	char dir_name[512];
	FILE * infile = NULL;

	int len = snprintf(dir_name, sizeof(dir_name), "%s/%s.key", seckey_dir, hexgrip);

	if (len < (int) sizeof(dir_name)) {
		infile = fopen(dir_name, mode);
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
open_curve25519_seckey_file(const char * seckey_dir, const char * mode, const u_char * q, int q_len)
{
	u_char keygrip[SHA_DIGEST_LENGTH];
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
 *  For an input path, generate an associated file name for the output (by appending ".iron"). If that file
 *  already exists, generate a file name using mkstemps.
 *
 *  @param fname Name of input file
 *  @param enc_fname Place to write name of output file. Should point to at least PATH_MAX chars
 *  @return FILE * NULL if unsuccessful, pointer to open file otherwise
 */
static FILE *
open_encrypted_output_file(const char * fname, char * enc_fname)
{
	if (strlen(fname) > PATH_MAX - 6 - IRON_SECURE_FILE_SUFFIX_LEN) {
		error("Input file name too long to append \"%s\".", IRON_SECURE_FILE_SUFFIX);
		return NULL;
	}

	FILE * out_file = NULL;
	
	strcpy(enc_fname, fname);
	strcat(enc_fname, IRON_SECURE_FILE_SUFFIX);

	if (access(enc_fname, F_OK) == 0) {
		sprintf(enc_fname, "%s_XXXX%s", fname, IRON_SECURE_FILE_SUFFIX);
		int fd = mkstemps(enc_fname, IRON_SECURE_FILE_SUFFIX_LEN);
		if (fd > 0) out_file = fdopen(fd, "w+");
	} else {
		out_file = fopen(enc_fname, "w+");
	}

	if (out_file == NULL) {
		error("Could not open output file \"%s\" to hold encrypted data from \"%s\".", enc_fname, fname);
	}

	return out_file;
}

/**
 *  Open file to which to write decrypted data.
 *
 *  Given the path of the encrypted file, generate path to which to write decrypted data by stripping ".iron"
 *  from the name. If the input file name doesn't have a .iron extension, return an error. Open the generated
 *  path name for write+ - will overwrite if the file exists.
 *
 *  @param fname Path of input file
 *  @param dec_fname Place to write name of output file. Should be at least PATH_MAX bytes
 *  @return FILE * Opened output file, NULL if unable to open for output.
 */
static FILE *
open_decrypted_output_file(const char * fname, char * dec_fname)
{
	if (strlen(fname) > PATH_MAX - 1) {
		error("Name of encrypted file, \"%s\", is too long.", fname);
		return NULL;
	}

	FILE * out_file = NULL;
	strcpy(dec_fname, fname);
	int offset = iron_extension_offset(dec_fname);

	if (offset > 0) {
		dec_fname[offset] = '\0';
		out_file = fopen(dec_fname, "w+");
		if (out_file == NULL) {
			error("Could not open output file \"%s\" to hold decrypted data from \"%s\".", dec_fname, fname);
		}
	} else {
		error("Expect the file to be decrypted to have a \"%s\" extension,\n   but \"%s\" does not.",
			  IRON_SECURE_FILE_SUFFIX, fname);
	}

	return out_file;
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
 *  @param rsa_key Key to use to sign message. Secret parms will be populated if they are not already
 *  @return int 0 if successful, negative number if error
 */
static int
write_encrypted_data_file(FILE * infile, const char * fname, const u_char * sym_key, Key * rsa_key,
						  const u_char * rsa_key_id, FILE * outfile)
{
	int retval = -1;

	//  Set up the SHA1 hash that will accumulate the literal data and generate the MDC packet at the end,
	//  and the SHA256 hash we use for the signature packet
	SHA_CTX mdc_ctx;
	SHA1_Init(&mdc_ctx);
	SHA256_CTX sig_ctx;
	SHA256_Init(&sig_ctx);

	//  Set up the AES256 cipher to encrypt the literal data
	EVP_CIPHER_CTX aes_ctx;
	const EVP_CIPHER * aes_cipher = EVP_aes_256_cfb();
	EVP_CIPHER_CTX_init(&aes_ctx);
	if (EVP_EncryptInit_ex(&aes_ctx, aes_cipher, NULL /* dflt engine */, sym_key, NULL /* dflt iv */)) {
		//  First output the start of the Symmetrically Encrypted Integrity Protected Data Packet.
		//  This requires that we know how long the data packet will be, so retrieve the file size.
		struct stat statstr;
		fstat(fileno(infile), &statstr);

		//  The SEIPD packet will wrap a one-pass signature packet, a literal data packet, and a signature
		//  packet. Need to figure out how long they are going to be as well. Go ahead and generate the OPS
		//  packet and header so we know their length, then generate the literal data packet header.
		gpg_message ops_pkt;
		generate_gpg_one_pass_signature_packet(rsa_key_id, &ops_pkt);
		u_char ops_hdr[7];
		int ops_hdr_len = generate_tag_and_size(ops_pkt.tag, ops_pkt.len, ops_hdr);

		u_char data_pkt_hdr[128];
		int data_pkt_hdr_len = generate_gpg_literal_data_packet(fname, statstr.st_size, statstr.st_mtime,
				data_pkt_hdr);

		//  Now generate the signature packet - we can get everything except the actual signature data. The
		//  length generated for the packet includes the signature that will be populated later.
		gpg_message sig_pkt;
		generate_gpg_data_signature_packet(rsa_key, rsa_key_id, &sig_pkt);
		u_char sig_hdr[7];
		int sig_hdr_len = generate_tag_and_size(sig_pkt.tag, sig_pkt.len, sig_hdr);

		//  Add everything together to get the SEIPD packet size: random data prefix, OPS, literal data,
		//  signature, and MDC packets, plus the SEIPD version # prefix
		int data_len = 1 /* version */ + AES_BLOCK_SIZE + 2 /* random data prefix */ + 
					   ops_hdr_len + ops_pkt.len /* OPS packet */+
					   data_pkt_hdr_len + statstr.st_size /* literal data packet */ +
					   sig_pkt.len + sig_hdr_len + /* signature packet */
					   GPG_MDC_PKT_LEN;

		u_char seipd_hdr[7];
		int seipd_hdr_len = generate_tag_and_size(GPG_TAG_SEIP_DATA, data_len, seipd_hdr);

		seipd_hdr[seipd_hdr_len] = GPG_SEIPD_VERSION;
		seipd_hdr_len++;

		//  Start emitting the SEIP packet.
		fwrite(seipd_hdr, 1, seipd_hdr_len, outfile);

		//  From this point, everything is hashed and encrypted. Start with the random prefix bytes, then the
		//  last two bytes repeated.
		u_char input[128];
		u_char output[128];
		randombytes_buf(input, AES_BLOCK_SIZE);
		input[AES_BLOCK_SIZE] = input[AES_BLOCK_SIZE - 2];
		input[AES_BLOCK_SIZE + 1] = input[AES_BLOCK_SIZE - 1];

		u_char * outp = output + hashcrypt(&mdc_ctx, NULL, &aes_ctx, input, AES_BLOCK_SIZE + 2, output);

		//  Add the one pass signature packet.
		outp += hashcrypt(&mdc_ctx, NULL, &aes_ctx, ops_hdr, ops_hdr_len, outp);
		outp += hashcrypt(&mdc_ctx, NULL, &aes_ctx, sshbuf_ptr(ops_pkt.data), ops_pkt.len, outp);

		//  Add the header for the Literal Data Packet
		outp += hashcrypt(&mdc_ctx, NULL, &aes_ctx, data_pkt_hdr, data_pkt_hdr_len, outp);
		fwrite(output, 1, outp - output, outfile);

		//  Now we start accumulating the hash for the signature packet as well, while we read and
		//  encrypt the file data.
		int total_read = encrypt_input_file(infile, outfile, &mdc_ctx, &sig_ctx, &aes_ctx);
		if (total_read >= 0) {
			if ((off_t) total_read == statstr.st_size) {
				//  Finish off the signature hash, then sign it and write the signature packet.
				if (finalize_gpg_data_signature_packet(&sig_ctx, rsa_key, &sig_pkt) == 0) {
					outp = output;
					outp += hashcrypt(&mdc_ctx, NULL, &aes_ctx, sig_hdr, sig_hdr_len, outp);
					outp += hashcrypt(&mdc_ctx, NULL, &aes_ctx, sshbuf_ptr(sig_pkt.data), sig_pkt.len, outp);
					fwrite(output, 1, outp - output, outfile);
					retval = write_gpg_mdc_packet(outfile, &mdc_ctx, &aes_ctx);
				} else {
					error("Unable to retrieve secret RSA key to sign message.");
				}
			} else {
				error("Did not read the complete input file.");
			}
		}

		EVP_CIPHER_CTX_cleanup(&aes_ctx);
	}

	return retval;
}

/**
 *  Retrieve public part of signing and encryption key pairs for specified login.
 *
 *  Attempt to read the public parts of the signing (RSA) key and encryption (cv25519) keys from the
 *  specified login's ~/.pubkey file. If that file is not available, read the public RSA key and
 *  encryption subkey for the login from the ~<login>/.ssh/pubkey.gpg file.
 *
 *  @param login Name of the user for whom to find the key
 *  @param key Place to put public portion of Curve25519 key (at least crypto_box_PUBLICKEYBYTES bytes)
 *  @param key_len Place to put num bytes in key
 *  @param fp Place to put fingerprint of Curve25519 key (at least GPG_KEY_FP_LEN bytes)
 *  @param rsa_key Place to put public portion of RSA key
 *  @param rsa_fp Place to put fingerprint of RSA key (at least GPG_KEY_FP_LEN bytes)
 *  @return int 0 if successful, negative number if error
 */
static int
get_public_keys(const char * login, Key * rsa_key, u_char * rsa_fp, u_char * key,
				size_t * key_len, u_char * fp)
{
	int retval = read_pubkey_file(login, rsa_key, rsa_fp, key, key_len, fp, NULL);
	if (retval != 0) {
		//  Couldn't get data from the user's .pubkey file - fetch from pubring.gpg
		char key_file_name[PATH_MAX];
		FILE * key_file;

		const char * ssh_dir = get_user_ssh_dir(login);
		snprintf(key_file_name, PATH_MAX, "%s%s", ssh_dir, GPG_PUBLIC_KEY_FNAME);
		key_file = fopen(key_file_name, "r");
		if (key_file != NULL) {
			retval = 0;

			gpg_message * pubkey_pkt = get_pub_key_packet(key_file);
			if (pubkey_pkt != NULL) {
				compute_gpg_key_fingerprint(pubkey_pkt, rsa_fp);
				retval = extract_gpg_rsa_pubkey(pubkey_pkt->data, rsa_key);
				sshbuf_free(pubkey_pkt->data);
				free(pubkey_pkt);
			} else {
				retval = -1;
			}
			if (retval == 0) {
				gpg_message * subkey_pkt = get_curve25519_key_packet(key_file);
				if (subkey_pkt != NULL) {
					const u_char * key_ptr = sshbuf_ptr(subkey_pkt->data) + sizeof(curve25519_oid) + 6;
					*key_len = (*key_ptr << 8) + *(key_ptr + 1);
					//  Size in bits from the header of the MPI - convert to bytes, then deduct leading 0x40
					*key_len = (*key_len + 7) / 8;
					(*key_len)--;
					key_ptr += 2;
					if (*(key_ptr++) == GPG_ECC_PUBKEY_PREFIX) {
						memcpy(key, key_ptr, *key_len);
						compute_gpg_key_fingerprint(subkey_pkt, fp);
						sshbuf_free(subkey_pkt->data);
						free(subkey_pkt);
					} else {
						error("Invalid format for public encryption key - could not recover data.");
						retval = -1;
					}
				} else {
					error("Unable to retrieve public encryption key - could not recover data.");
					retval = -1;
				}
			}
			fclose(key_file);
		}
	}

	return retval;
}

/**
 *  Retrieve secret part of RSA signing key pair.
 *
 *  Retrieve the secret RSA signing key for the login that is running the process. Given the public
 *  keys for that user, uses the public encryption key to compute the keygrip, open the secret key file, then
 *  retrieve the secret key from that file. This requires the passphrase, which requires the RSA public key as well
 *  (to generate the passphrase).
 *
 *  @param keys Input has public keys. If successful, private part of RSA key is populated
 *  @return int 0 if successful, negative number if error
 */
static int
get_secret_signing_key(Key * rsa_key)
{
	int retval = -1;
	const char * ssh_dir = get_user_ssh_dir(user_login);
	char * seckey_dir = check_seckey_dir(ssh_dir);
	if (seckey_dir != NULL) {
		FILE * infile = open_rsa_seckey_file(seckey_dir, "r", rsa_key);
		if (infile != NULL) {
			u_char buf[4096];		//  Just picked a big number to hold entire file

			int num_read = fread(buf, 1, sizeof(buf), infile);
			retval = extract_gpg_rsa_seckey(buf, num_read, rsa_key);
			fclose(infile);
		}

		free(seckey_dir);
	}

	return retval;
}

/**
 *  Retrieve secret part of cv25519 encryption key pair.
 *
 *  Retrieve the secret curve25519 encryption key for the login that is running the process. Given the public
 *  keys for that user, uses the public encryption key to compute the keygrip, open the secret key file, then
 *  retrieve the secret key from that file. This requires the passphrase, which requires the RSA public key as well
 *  (it is used to generate the passphrase).
 *
 *  @param pub_keys public rsa and cv25519 keys - uses cv25519 key to generate keygrip, rsa key for passphrase
 *  @param sec_key Place to put secret part of curve25519 key (at least crypto_box_SECRETKEYBYTES bytes)
 *  @return int num bytes in sec_key if successful, negative number if error
 */
static int
get_secret_encryption_key(const gpg_public_key * pub_keys, u_char * sec_key)
{
	static u_char cached_sec_key[crypto_box_SECRETKEYBYTES];
	static size_t cached_sec_key_len = 0;

	if (cached_sec_key_len > 0) {
		memcpy(sec_key, cached_sec_key, cached_sec_key_len);
		return cached_sec_key_len;
	}
	
	int retval = -1;
	const char * ssh_dir = get_user_ssh_dir(user_login);
	char * seckey_dir = check_seckey_dir(ssh_dir);
	if (seckey_dir != NULL) {
		FILE * infile = open_curve25519_seckey_file(seckey_dir, "r", pub_keys->key, sizeof(pub_keys->key));
		if (infile != NULL) {
			u_char buf[4096];

			int num_read = fread(buf, 1, sizeof(buf), infile);
			retval = extract_gpg_curve25519_seckey(buf, num_read, &(pub_keys->rsa_key), sec_key);
			if (retval > 0) {
				cached_sec_key_len = retval;
				memcpy(cached_sec_key, sec_key, retval);
			}
			fclose(infile);
		}

		free(seckey_dir);
	}

	return retval;
}

/**
 *  Read login's ~/.pubkey file.
 *
 *  Retrieve the IronCore public key entries from the specified login's .pubkey file.
 *
 *  @param login User whose key info to retrieve
 *  @param rsa_key Output - public portion of RSA key from .pubkey. Should point to at least GPG_MAX_KEY_SIZE bytes
 *  @param rsa_key_len Output - num bytes in rsa_key
 *  @param cv25519_key Output - public portion of Curve25519 key - at least crypto_box_SECRETKEYBYTES bytes
 *  @param cv25519_key_len Output - num bytes in cv25519_key
 *  @param rsa_fp Output - fingerprint of RSA key. Point to at least GPG_KEY_FP_LEN bytes
 *  @param cv25519_fp Output - fingerprint of Curve25519 key. Point to at least GPG_KEY_FP_LEN bytes
 *  @param uid Output - the "user ID" string associated with the keys. Should point to at least GPG_MAX_UID_LEN bytes
 *  @return int 0 if successful, negative number if error
 */
static int
read_pubkey_file(const char * login, Key * rsa_key, u_char * rsa_fp, u_char * cv25519_key,
				 size_t * cv25519_key_len, u_char * cv25519_fp, char * uid)
{
	int retval = -1;

#define SET_IF_NOT_NULL(fld) if ((fld) != NULL) *(fld) = '\0'

	if (rsa_key != NULL) {
		RSA_free(rsa_key->rsa);
		rsa_key->rsa = NULL;
	}
	SET_IF_NOT_NULL(rsa_fp);
	SET_IF_NOT_NULL(cv25519_key);
	SET_IF_NOT_NULL(cv25519_fp);
	SET_IF_NOT_NULL(uid);

	struct passwd * pw = getpwnam(login);
	if (pw != NULL) {
		char fname[PATH_MAX];
		snprintf(fname, PATH_MAX, "%s/.pubkey", pw->pw_dir);

		FILE * infile = fopen(fname, "r");
		if (infile != NULL) {
			retval = 0;
			char line[3000];
			while (fgets(line, sizeof(line), infile)) {
				char * lptr = line;
				char * token;
				if (strncmp(line, "iron-rsa:", 9) == 0) {
					token = strsep(&lptr, " ");		// Skip initial "iron-rsa: "
					token = strsep(&lptr, " ");		// Next string should be the n value
					if (rsa_key != NULL) {
						u_char tval[GPG_MAX_KEY_SIZE];
						int tlen = str2hex(token, tval, GPG_MAX_KEY_SIZE);

						if (tlen > 0) {
							rsa_key->rsa = RSA_new();
							rsa_key->rsa->n = BN_new();
							BN_bin2bn(tval, tlen, rsa_key->rsa->n);
							token = strsep(&lptr, " ");		// Next string should be the e value
							int tlen = str2hex(token, tval, GPG_MAX_KEY_SIZE);
							if (tlen > 0) {
								rsa_key->rsa->e = BN_new();
								BN_bin2bn(tval, tlen, rsa_key->rsa->e);
							} else {
								retval = -1;
								break;
							}
						} else {
							retval = -1;
							break;
						}
					} else {
						token = strsep(&lptr, " ");		// Skip the e value
					}
					token = strsep(&lptr, " ");
					if (rsa_fp != NULL) {
						int fp_len = str2hex(token, rsa_fp, GPG_KEY_FP_LEN);
						if (fp_len != GPG_KEY_FP_LEN) {
							retval = -1;
							break;
						}
					}
					if (uid != NULL) {
						token = strsep(&lptr, " ");
						strlcpy(uid, token, GPG_MAX_UID_LEN);
					}
				} else if (strncmp(line, "iron-cv25519:", 13) == 0) {
					token = strsep(&lptr, " ");		// Skip initial "iron-cv25519: "
					token = strsep(&lptr, " ");
					if (cv25519_key != NULL) {
						int klen = str2hex(token, cv25519_key, crypto_box_SECRETKEYBYTES);
						if (klen >= 0) {
							*cv25519_key_len = klen;
						} else {
							retval = -1;
							break;
						}
					}
					token = strsep(&lptr, " ");
					if (rsa_fp != NULL) {
						if (str2hex(token, cv25519_fp, GPG_KEY_FP_LEN) != GPG_KEY_FP_LEN) {
							retval = -1;
							break;
						}
					}
					//  Ignore the uid on the subkey line
				}
			}
		}
	}

	if (retval == 0) {
		//  Make sure that we actually got all the requested parts
		if (rsa_key != NULL && rsa_key->rsa == NULL) {
			error("Didn't find RSA key in file.");
			retval = -1;
		}

#define ERR_IF_EMPTY_STR(fld, name) if ((fld) != NULL && *(fld) == '\0') { \
	error("Didn't find " name " in file."); retval = -1; }

		ERR_IF_EMPTY_STR(rsa_fp, "RSA key fingerprint");
		ERR_IF_EMPTY_STR(cv25519_key, "Curve25519 key");
		ERR_IF_EMPTY_STR(cv25519_fp, "Curve25519 key fingerprint");
		ERR_IF_EMPTY_STR(uid, "User ID");
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
write_trustdb_htbl(FILE * tdb_file, const u_char * key, int key_len)
{
	u_char tdb_rec[GPG_TRUST_REC_SIZE];
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
generate_gpg_trustdb_version(u_char * rec)
{
	u_char * recp = rec;

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
	int_to_buf(gpg_now, recp);		   recp += 4;
	/*  Leave next check 0  */ 		   recp += 4;
	/*  Skip reserved  */              recp += 8;
	/*  Leave first free 0  */         recp += 4;
	/*  Skip reserved  */              recp += 4;
	int_to_buf(1, recp); 				/*  Rec # of start of hash table is 1  */
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
generate_gpg_trustdb_trust(u_char * rec, const u_char * key, int key_len, int next_rec)
{
	u_char * recp = rec;

	bzero(rec, GPG_TRUST_REC_SIZE);
	*recp = GPG_TRUST_RECTYPE_TRUST;   recp++;
	/*  Skip reserved  */  			   recp++;
	memcpy(recp, key, key_len);		   recp += key_len;
	*recp = GPG_TRUST_ULTIMATE;        recp++;
	/*  Leave depth 0 */  			   recp++;
	/*  Leave min owner trust 0 */     recp++;
	/*  Skip reserved  */  			   recp++;
	int_to_buf(next_rec, recp);
}

/**
 *  Generate the "valid" packet for trustDB file.
 *
 *  @param rec Place to write generated packet (at least 28 bytes)
 *	@param uid String identifying user (typically "Name <emailaddr>")
 */
static void
generate_gpg_trustdb_valid(u_char * rec, const char * uid)
{
	u_char * recp = rec;

	bzero(rec, GPG_TRUST_REC_SIZE);
	*recp = GPG_TRUST_RECTYPE_VALID;   recp++;
	/*  Skip reserved  */  			   recp++;
	
	/* Compute the RIPE-MD160 hash of the UID. Yes, RIPE-MD160. Thanks, GPG. */
	u_char hash[RIPEMD160_DIGEST_LENGTH];
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
write_trustdb_file(const char * ssh_dir, const u_char * key, size_t key_len, const char * uid)
{
	int retval = -1;

	char file_name[PATH_MAX];
	snprintf(file_name, PATH_MAX, "%s%s", ssh_dir, GPG_TRUSTDB_FNAME);
	FILE * tdb_fp = fopen(file_name, "w");
	if (tdb_fp != NULL) {
		fchmod(fileno(tdb_fp), S_IRUSR | S_IWUSR);

		u_char tdb_rec[GPG_TRUST_REC_SIZE];

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
//  Functions to generate the GPG key files - only used when check_iron_files
//  detects that they aren't present and it needs to create them.
//================================================================================


/**
 *  Copy one of the SSH key files to a .iron backup copy.
 *
 *  Caller can specify an empty extension, "", to copy the secret key file, or the public extension,
 *  SSH_KEY_PUB_EXT, to copy the public key file.
 *
 *  It is an error if the destination file already exists.
 *
 *  @param ssh_dir path to directory that holds key files
 *  @param ext extension for key file
 *  @return int 0 if copy successful, negative number if error
 */
static int
copy_ssh_key_file(const char * ssh_dir, const char * ext)
{
	int retval = -1;
	char cp_cmd[2 * PATH_MAX + 4];   //  Room for "cp " and two file names, space-separated, with NULL term.

	char ssh_key_file[PATH_MAX];
	snprintf(ssh_key_file, PATH_MAX, "%s%s%s", ssh_dir, SSH_KEY_FNAME, ext);

	if (access(ssh_key_file, F_OK) == 0) {
		char iron_key_file[PATH_MAX];
		snprintf(iron_key_file, PATH_MAX, "%s%s%s", ssh_dir, IRON_SSH_KEY_FNAME, ext);

		if (access(iron_key_file, F_OK) != 0) {
			snprintf(cp_cmd, sizeof(cp_cmd), "cp %s %s", ssh_key_file, iron_key_file);
			if (system(cp_cmd) == 0) {
				retval = 0;
			} else {
				error("Cannot copy \"%s\" to \"%s\".", ssh_key_file, iron_key_file);
			}
		} else {
			error("Destination key file \"%s\" already exists.", iron_key_file);
		}
	} else {
		error("Cannot find key file \"%s\".", ssh_key_file);
	}
	
	return retval;
}

/**
 *  Copy the private and public SSH key files to .iron copies
 *
 *  @param ssh_dir path to directory that holds key files
 *  @return int 0 if copy successful, negative number if error
 */
static int
copy_ssh_key_files(const char * ssh_dir)
{
	int retval = -1;

	if (copy_ssh_key_file(ssh_dir, "") == 0) {
		if (copy_ssh_key_file(ssh_dir, SSH_KEY_PUB_EXT) == 0) {
			retval = 0;
		}
	}

	return retval;
}

/**
 *  Attempt to load SSH private key from specified file.
 *
 *  Prompt the user for the passphrase, then attempt to retrieve key.
 *
 *  @param ssh_key_file Name of file to read
 *  @param prompt Text to display when asking user to enter passphrase
 *  @param key Place to write recovered private key
 *  @param comment Place to write comment associated with key
 *  @return int 0 if successful, negative number if error
 */
static int
load_ssh_private_key(const char * ssh_key_file, const char * prompt, Key ** key)
{
	char * passphrase = read_passphrase(prompt, 0);
	int retval = sshkey_load_private(ssh_key_file, passphrase, key, NULL);
	explicit_bzero(passphrase, strlen(passphrase));
	free(passphrase);
	return retval;
}

/**
 *  Retrieve SSH private key from .ssh directory.
 *
 *  Try to fetch the private key from the id_rsa.iron file. Includes retries if user enters incorrect passphrase.
 *
 *  @param ssh_dir Name of directory from which to read file
 *  @param prompt String to display to user before reading passphrase ("" to suppress prompt and use no passphrase)
 *  @param key Place to write SSH key read from file.  Caller should sshkey_free
 *  @returns int 0 if successful, negative number if error
 */
static int
retrieve_ssh_private_key(const char * ssh_dir, const char * prompt, Key ** key)
{
	int retval = -1;

	char ssh_key_file[PATH_MAX];
	snprintf(ssh_key_file, PATH_MAX, "%s%s", ssh_dir, IRON_SSH_KEY_FNAME);

	//  Attempt to load the key with no passphrase, just in case
	retval = sshkey_load_private(ssh_key_file, "", key, NULL);
	if (retval == SSH_ERR_KEY_WRONG_PASSPHRASE) {
		int retry_ct = 0;
		retval = load_ssh_private_key(ssh_key_file, prompt, key);
		while (retval == SSH_ERR_KEY_WRONG_PASSPHRASE && retry_ct < MAX_PASSPHRASE_RETRIES) {
			retval = load_ssh_private_key(ssh_key_file, "Incorrect passphrase - try again: ", key);
			retry_ct++;
		}
	}

	return retval;
}

/**
 *  Retrieve SSH public key's comment from .ssh directory.
 *
 *  Try to fetch the public key from the id_rsa.iron.pub file. Actually only need the comment from it -
 *  the public key parameters were fetched along with the private key parameters by retrieve_ssh_private_key.
 *
 *  @param ssh_dir Name of directory from which to read file
 *  @param comment Place to write comment string read from file. Caller should free
 *  @returns int 0 if successful, negative number if error
 */
static int
retrieve_ssh_public_key(const char * ssh_dir, char ** comment)
{
	int retval = -1;

	char ssh_key_file[PATH_MAX];
	snprintf(ssh_key_file, PATH_MAX, "%s%s%s", ssh_dir, SSH_KEY_FNAME, SSH_KEY_PUB_EXT);

	Key * tmp_key;
	retval = sshkey_load_public(ssh_key_file, &tmp_key, comment);
	if (retval == 0) {
		sshkey_free(tmp_key);
	}

	return retval;
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
 *  @param key Place to write pointer to key read from file. Caller should sshkey_free
 *  @param comment Place to write pointer to comment read from public key file. Caller should free
 */
static int
retrieve_ssh_key(const char * const ssh_dir, Key ** key, char ** comment)
{
	int retval = retrieve_ssh_private_key(ssh_dir, "Enter passphrase for SSH key file: ", key);

	//  If we succeeded in reading the private key, read the public key to get the comment field,
	//  which will typically be the user's identification (i.e. email address)
	if (retval == 0) {
		retval = retrieve_ssh_public_key(ssh_dir, comment);
	}

	return retval;
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
write_public_key_file(FILE * pub_file, const Key * ssh_key, const u_char * pub_subkey,
					  const char * uid, u_char * key_fp, u_char * subkey_fp)
{
	int retval = -1;
	gpg_message public_key_pkt;
	gpg_message user_id_pkt;
	gpg_message sig_pkt;
	gpg_message trust_pkt;

	generate_gpg_public_key_packet(ssh_key, &public_key_pkt);
	compute_gpg_key_fingerprint(&public_key_pkt, key_fp);
	u_char * key_id = key_fp + GPG_KEY_ID_OFFSET;  //  Last 8 bytes of fingerprint

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
 *  are encrypted, using the supplied passphrase to generate the key. If the secret key files already exist,
 *  they are overwritten.
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
write_secret_key_files(const char * ssh_dir, const Key * ssh_key, const u_char * q, int q_len,
					   const u_char * d, int d_len, const char * passphrase)
{
	int retval = -1;
	char * seckey_dir = check_seckey_dir(ssh_dir);

	if (seckey_dir) {
		FILE * rsa_key_file = open_rsa_seckey_file(seckey_dir, "w", ssh_key);

		if (rsa_key_file != NULL) {
			fchmod(fileno(rsa_key_file), S_IRUSR | S_IWUSR);	//  600 perms.

			struct sshbuf * rsa_seckey = generate_gpg_rsa_seckey(ssh_key, passphrase);
			if (rsa_seckey != NULL) {
				if (fwrite(sshbuf_ptr(rsa_seckey), 1, sshbuf_len(rsa_seckey), rsa_key_file) ==
							sshbuf_len(rsa_seckey)) {
					FILE * c_key_file = open_curve25519_seckey_file(seckey_dir, "w", q, q_len);
					if (c_key_file != NULL) {
						fchmod(fileno(c_key_file), S_IRUSR | S_IWUSR);	//  600 perms.
						struct sshbuf * c_seckey = generate_gpg_curve25519_seckey(q, q_len, d, d_len, passphrase);
						if (c_seckey != NULL) {
							if (fwrite(sshbuf_ptr(c_seckey), 1, sshbuf_len(c_seckey), c_key_file) ==
										sshbuf_len(c_seckey)) {
								retval = 0;
							}
							sshbuf_free(c_seckey);
						}
						fclose(c_key_file);
					}
				}
				sshbuf_free(rsa_seckey);
			}
			fclose(rsa_key_file);
		}
		free(seckey_dir);
	}
	return retval;
}

/**
 *  Write a line to the user's .pubkey file containing specified RSA key info.
 *
 *  Write the key name, public key n, public key e, fingerprint, and UID in one line to the file.
 *  Writes the key name as "iron-rsa".
 *
 *  @param outfile File to which to write line
 *  @param key RSA key to write as two hex strings (n and e)
 *  @param fp Byte array containing key fingerprint. Converted to hax string
 *	@param uid String identifying user (typically "Name <emailaddr>")
 *  @return int 0 if successful, negative number if error
 */
static int
write_rsa_key_to_pubkey(FILE * outfile, const Key * rsa_key, const u_char * fp, const char * uid)
{
	int retval = -1;

	u_char pval[GPG_MAX_KEY_SIZE];
	int plen;
	u_char tmp[2 * GPG_MAX_KEY_SIZE + 1];
	plen = BN_bn2bin(rsa_key->rsa->n, pval);
	hex2str(pval, plen, tmp);
	if (fprintf(outfile, "iron-rsa: %s ", tmp) > 0) {
		plen = BN_bn2bin(rsa_key->rsa->e, pval);
		hex2str(pval, plen, tmp);
		fprintf(outfile, "%s ", tmp);
		hex2str(fp, GPG_KEY_FP_LEN, tmp);
		if (fprintf(outfile, "%s %s\n", tmp, uid) > 0) {
			retval = 0;
		}
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
write_key_to_pubkey(FILE * outfile, const char * key_name, const u_char * pub_key, int len,
					const u_char * fp, const char * uid)
{
	int retval = -1;

	u_char tmp[2 * GPG_MAX_KEY_SIZE + 1];
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
 *  @param rsa_key RSA key to write to file (only need public params n and e populated)
 *  @param subkey Public cv25519 key
 *	@param uid String identifying user (typically "Name <emailaddr>")
 *	@param key_fp Byte array containing fingerprint for RSA key
 *	@param subkey_fp Byte array containing fingerprint for cv25519 key
 *  @return int 0 if successful, negative number if error
 */
static int
write_pubkey_file(const char * login, Key * rsa_key, const u_char * key_fp, const u_char * subkey,
				  const u_char * subkey_fp, const char * uid)
{
	int retval = -1;

	char fname[PATH_MAX];
	struct passwd * pw = getpwnam(login);
	if (pw != NULL) {
		snprintf(fname, PATH_MAX, "%s/.pubkey", pw->pw_dir);

		FILE * outfile = NULL;
		int shuffle_files;
		char tname[PATH_MAX];
		FILE * infile;

		if (access(fname, F_OK) == 0) {
			//  File already exists - copy all the non-IronCore lines from it to a new file
			shuffle_files = 1;
			infile = fopen(fname, "r");
			if (infile != NULL) {
				snprintf(tname, PATH_MAX, "%s/.pubkey.XXXXXX", pw->pw_dir);
				int fd = mkstemp(tname);
				if (fd > 0) outfile = fdopen(fd, "w");
				if (outfile != NULL) {
					//  Arbitrarily chose a length to handle long lines in input file. However, if a line
					//  is longer than that length and gets split across multiple fgets() calls, make sure
					//  to discard or keep the entire line.
					char line[301];
					int at_start_of_line = 1;
					int discard_next = 0;
					while (fgets(line, sizeof(line), infile)) {
						int skip_output = (discard_next || (strncmp(line, "iron-", 5) == 0 && at_start_of_line));
						if (!skip_output) fputs(line, outfile);
						at_start_of_line = (line[strlen(line) - 1] == '\n');
						discard_next = skip_output && !at_start_of_line;
					}
				} else {
					error("Unable to open temporary file for output to copy pubkey file.");
				}
			} else {
				error("Unable to open \"%s\" for input.", fname);
			}
		} else {
			//  Starting with a fresh file
			shuffle_files = 0;
			outfile = fopen(fname, "w");
		}

		if (outfile != NULL) {
			if (write_rsa_key_to_pubkey(outfile, rsa_key, key_fp, uid) == 0) {
				if (write_key_to_pubkey(outfile, "cv25519", subkey, crypto_box_PUBLICKEYBYTES, subkey_fp,
							uid) == 0) {
					fchmod(fileno(outfile), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
					fclose(outfile);

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
 *  @return int 0 if successful, negative number if error
 */
static int
generate_iron_keys(const char * const ssh_dir, const char * const login)
{
	int retval = -1;
	if (ssh_dir != NULL && *ssh_dir) {
		printf("\nYou do not appear to have IronCore keys in your .ssh directory\n"
			   "(%s), so they will be generated them for you.\n\n"
			   "To do this, you need to have an RSA key stored in ~/.ssh/%s.\n"
			   "(This key should be protected by a passphrase!)\n"
			   "Your %s file will be copied to ~/.ssh/%s, and your %s.pub\n"
			   "file to ~/.ssh/%s.pub. The %s file will be opened to\n"
			   "retrieve the RSA key. This may prompt you to enter your passphrase.\n"
			   "Please do so.\n\n"
			   "Once you have successfully entered your passphrase, the RSA key will be\n"
			   "retrieved and used to create a new key file, ~/.ssh/%s.\n"
			   "Your SSH RSA key will be added as the master key in that file, and a\n"
			   "new encryption key will be generated and added as a subkey.\n\n"
			   "These keys will be used to transparently encrypt any file that you upload\n"
			   "(via 'put'), and to decrypt any file that you download (via 'get').\n\n"
			   "Note that the new key files that are generated are compatible with GPG\n"
			   "v. 2.1.14 and newer.\n\n",
			   ssh_dir, SSH_KEY_FNAME, SSH_KEY_FNAME, IRON_SSH_KEY_FNAME, SSH_KEY_FNAME, IRON_SSH_KEY_FNAME,
			   IRON_SSH_KEY_FNAME, GPG_PUBLIC_KEY_FNAME);

		u_char pub_key[crypto_box_PUBLICKEYBYTES];
		u_char sec_key[crypto_box_SECRETKEYBYTES];
		crypto_box_keypair(pub_key, sec_key);
		clamp_and_reverse_seckey(sec_key);

		Key * ssh_key;
		char * comment;

		if (copy_ssh_key_files(ssh_dir) == 0 && retrieve_ssh_key(ssh_dir, &ssh_key, &comment) == 0) {
			char file_name[PATH_MAX];
			snprintf(file_name, PATH_MAX, "%s%s", ssh_dir, GPG_PUBLIC_KEY_FNAME);
			FILE * pub_file = fopen(file_name, "w");
			if (pub_file != NULL) {
				u_char key_fp[GPG_KEY_FP_LEN];
				u_char subkey_fp[GPG_KEY_FP_LEN];

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
					char passphrase[512];
					if ((generate_gpg_passphrase_from_rsa(ssh_key, passphrase) == 0) &&
					    (write_secret_key_files(ssh_dir, ssh_key, pub_key, sizeof(pub_key), sec_key,
								sizeof(sec_key), passphrase) == 0)) {
						printf("\nGenerated new GPG secret keys - they are protected with the passphrase\n"
							   "    %s\n\n"
							   "You will need this passphrase if you want to decrypt any '.iron' files\n"
							   "directly with GPG. No need to store it, though - it is generated using\n"
							   "your SSH RSA key, so you can use the iron-passphrase utility to generate\n"
							   "it at any time. You just need to enter the passphrase for your RSA key.\n\n",
							   passphrase);

						if (write_trustdb_file(ssh_dir, key_fp, sizeof(key_fp), uid) == 0 &&
							write_pubkey_file(login, ssh_key, key_fp, pub_key, subkey_fp, uid) == 0) {
							retval = 0;
						}
					}
				}
				fclose(pub_file);
			} else {
				error("Unable to open \"%s\" to write public key.", file_name);
			}
		}
	}

	return retval;
}


//================================================================================
//  Publicly visible funcs
//================================================================================

/**
 *  Confirm that public and private key files are in place for the current user.
 *
 *  Check to see if the public/private key files containing the specified login's rsa & curve25519 keys
 *  exist and are accessible. If not, and if we have access to the login's .ssh directory, try to create
 *  new files.
 *
 *  @param login Login of the target user (usually the user running the executable)
 *  @return int zero if keys in place, negative number if error
 */
int
check_iron_keys(void)
{
	if (initialize() != 0) return -1;

	int retval = -1;
	const char * ssh_dir = get_user_ssh_dir(user_login);
	if (ssh_dir != NULL && *ssh_dir) {
		char file_name[PATH_MAX];
		snprintf(file_name, PATH_MAX, "%s%s", ssh_dir, GPG_PUBLIC_KEY_FNAME);

		if (access(file_name, F_OK) == 0) {
			char * seckey_dir = check_seckey_dir(ssh_dir);
			if (seckey_dir != NULL) {
				//  If the directory is there, assume that the key files are in place.
				retval = 0;
				free(seckey_dir);
			}
		}

		if (retval < 0) {
			if (errno == EACCES) {
				error("No access to the \"%s\" directory.", ssh_dir);
			}
			else if (errno == ENOENT) {
				//  Try to generate key pair and create files.
				retval = generate_iron_keys(ssh_dir, user_login);
			}
			else {
				error("Error checking \"%s\" - %s", file_name, strerror(errno));
			}
		}
	} else {
		error("Unable to find .ssh directory for user %s\n", user_login);
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
 *  @param enc_fname Output the path of the encrypted file - should point to at least PATH_MAX chars
 *  @return int - file number of the output file, or negative number if error
 */
int
write_gpg_encrypted_file(const char * fname, char * enc_fname)
{
	if (initialize() != 0) return -1;

	int retval = -1;
	FILE * infile = fopen(fname, "r");
	if (infile != NULL) {
		FILE * outfile = open_encrypted_output_file(fname, enc_fname);
		if (outfile != NULL) {
			u_char sym_key_frame[AES256_KEY_BYTES + AES_WRAP_BLOCK_SIZE];
			int frame_len = generate_gpg_sym_key_frame(sym_key_frame);
			if (frame_len == sizeof(sym_key_frame)) {
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
					//  The first recipient is always the current user - use that entry's key and key ID.
					//  We cheat and cast the const out of the recipient key pointer - we only ever write to
					//  the current user's key.
					retval = write_encrypted_data_file(infile, fname, sym_key_frame + 1,
						   							   (Key	*) &(recipient_key[0].rsa_key),
													   recipient_key[0].signer_fp + GPG_KEY_ID_OFFSET, outfile);
					if (retval == 0) {
						retval = fileno(outfile);
					}
				}
			} else {
				error("Unable to generate key to encrypt data.");
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
 *  @param dec_fname Place to write name of the output file that is created (at least PATH_MAX chars)
 *  @return 0 if successful, negative number if errors
 */
int
write_gpg_decrypted_file(const char * fname, char * dec_fname)
{
	if (initialize() != 0) return -1;

	FILE * infile = fopen(fname, "r");
	if (infile == NULL) {
		error("Could not open file \"%s\" for input.", fname);
		return -1;
	}

	int retval = -1;
	*dec_fname = '\0';
	u_char msg[512];
	gpg_tag next_tag;
	int     next_len;

	const gpg_public_key * pub_keys = get_recipient_keys(user_login);
	if (pub_keys == NULL) {
		error("Unable to retrieve public IronCore keys for user %s.", user_login);
		fclose(infile);
		return -1;
	}

	retval = get_gpg_pkesk_packet(infile, pub_keys->fp + GPG_KEY_ID_OFFSET, msg, &next_tag, &next_len);
	if (retval == 0) {
		u_char * msg_ptr = msg;
		if (*(msg_ptr++) == GPG_PKALGO_ECDH) {
			const u_char *ephem_pk;
			int ekey_offset = extract_ephemeral_key(msg_ptr, &ephem_pk);
			if (ekey_offset < 0) {
				fclose(infile);
				return -2;
			}
			msg_ptr += ekey_offset;

			//  If we are actually able to retrieve what we think is a PKESK packet, chances are good that
			//  this is really a file containing GPG encrypted data. Before we can get further, we need to
			//  retrieve the user's secret key.
			u_char sec_key[crypto_box_SECRETKEYBYTES];
			if (get_secret_encryption_key(pub_keys, sec_key) < 0) {
				fclose(infile);
				return -3;
			}

			u_char secret[crypto_box_BEFORENMBYTES];
			generate_curve25519_shared_secret(sec_key, ephem_pk, secret);

			u_char sym_key[AES256_KEY_BYTES];
			int rv = extract_sym_key(msg_ptr, secret, pub_keys->fp, sym_key);
			if (rv < 0) {
				fclose(infile);
				return -4;
			}

			//  The next header we read after we processed all the PKESK packets should be the SEIPD
			//  packet. After the header, there is a one byte version number, then encrypted data.
			//
			//  Note that the encrypted data will always be long enough to output at least two blocks (32
			//  bytes) in the first call to DecryptUpdate - the header + MDC packet is more than 32 bytes,
			//  even if the file name is 1 character long and the file is empty.
			u_char dec_buf[DECRYPT_CHUNK_SIZE + 2 * AES_BLOCK_SIZE];
			u_char seipd_ver = fgetc(infile);
			if (next_tag == GPG_TAG_SEIP_DATA && seipd_ver == GPG_SEIPD_VERSION) {
				SHA_CTX mdc_ctx;			//  One hash for the Modification Detection Code
				SHA1_Init(&mdc_ctx);
				SHA256_CTX sig_ctx;			//  One hash for the Signature packet
				SHA256_Init(&sig_ctx);

				EVP_CIPHER_CTX aes_ctx;
				const EVP_CIPHER * aes_cipher = EVP_aes_256_cfb();
				EVP_CIPHER_CTX_init(&aes_ctx);
				if (EVP_DecryptInit_ex(&aes_ctx, aes_cipher, NULL /*dflt engine*/, sym_key,
							NULL /*dflt iv*/)) {
					int num_dec;
					ssize_t len;
					int extra;
					char local_fname[PATH_MAX];
					u_char rsa_key_id[GPG_KEY_ID_LEN];

					int dec_offset = process_enc_data_hdr(&mdc_ctx, &aes_ctx, infile, dec_buf, rsa_key_id,
												  local_fname, &num_dec, &len, &extra);
					if (dec_offset < 0) {
						fclose(infile);
						return -5;
					}

					u_char * dptr = dec_buf + dec_offset;
					FILE * outfile = open_decrypted_output_file(fname, dec_fname);
					if (outfile != NULL) {
						//  Flush remainder of decrypted buffer that is file data. May still be some left that is
						//  all or part of the Sig/MDC packets.
						fwrite(dptr, 1, num_dec, outfile);
						SHA1_Update(&mdc_ctx, dptr, num_dec);
						SHA256_Update(&sig_ctx, dptr, num_dec);
						len -= num_dec;
						dptr += num_dec;

						//  If there is any Sig/MDC data in dec_buf, len will be zero, extra will be the number
						//  of bytes of that data
						retval = process_enc_data(&mdc_ctx, &sig_ctx, &aes_ctx, rsa_key_id, infile, outfile,
							   					  dec_buf, dptr - dec_buf, len, extra);

						if (retval == 0) {
							fflush(outfile);
							rewind(outfile);
							retval = fileno(outfile);
						}
					} else {
						error("Unable to open an output file to hold decrypted contents of \"%s\" -\n   %s.",
							  fname, strerror(errno));
					}
				}
			}
		} else {
			error("Invalid header on packet in data file - cannot recover data.");
		}
	}
	fclose(infile);

	return retval;
}


//================================================================================
//  Functions to manipulate list of registered recipients - the users with which
//  an uploaded file will be shared.  We have imposed a somewhat arbitrary limit
//  of 10 recipients (in addition to the current user) for file sharing.
//
//  The first entry in the list is always the current user, and that entry will
//  always be in the list.
//================================================================================
#define MAX_RECIPIENTS	11
static gpg_public_key recipient_list[11];
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
	if (num_recipients == 0) {
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
 *  Return the entry for a specific user.
 *
 *  The recipient entry has all the user's public key information.
 *
 *  @param login User whose entry to fetch
 *  @returns const gpg_public_key * Pointer to entry for the user, NULL if keys couldn't be retrieved
 */
static const gpg_public_key *
get_recipient_keys(const char * login)
{
	//  High tech linear search of recipient list. It should be short - don't freak out.
	const gpg_public_key * recip;
	int num_recip = get_recipients(&recip);
	int ct = 0;
	while (ct < num_recip && strcmp(login, recip->login) != 0) {
		recip++;
		ct++;
	}

	if (ct == num_recip) recip = NULL;
	return recip;
}

/**
 *  Return the entry for a specific key ID.
 *
 *  The recipient entry has all the user's public key information. It will return the first entry that
 *  matches the key ID in either the cv25519 or the RSA key ID.
 *
 *  @param key_id ID whose entry to fetch
 *  @returns const gpg_public_key * Pointer to entry for the user, NULL if keys couldn't be retrieved
 */
static const gpg_public_key *
get_recipient_keys_by_key_id(const char * key_id)
{
	//  Another linear search of recipient list - still no cause for alarm.
	const gpg_public_key * recip;
	int num_recip = get_recipients(&recip);
	int ct = 0;
	while (ct < num_recip && memcmp(key_id, recip->fp + GPG_KEY_ID_OFFSET, GPG_KEY_ID_LEN) != 0 && 
		   memcmp(key_id, recip->signer_fp + GPG_KEY_ID_OFFSET, GPG_KEY_ID_LEN) != 0) {
		recip++;
		ct++;
	}

	if (ct == num_recip) recip = NULL;
	return recip;
}
/**
 *  Add a recipient to registered list.
 *
 *  Add an entry for the specified user to the list of registered recipients. Requires that the user
 *  has a ~<login>/.pubkey file, or that we can access the user's ~<login>/.ssh/pubring.gpg file. (The
 *  latter probably only happens if the login is the user running the process.)
 *
 *  We have a lmit on the number that can be added - attempting to add one more is an error.
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
			error("User %s already in the recipient list.", login);
			retval = -1;
			break;
		}
	}

	if (retval == 0) {
		if (num_recipients < MAX_RECIPIENTS) {
			gpg_public_key * new_ent = recipient_list + num_recipients;
			strncpy(new_ent->login, login, MAX_LOGIN_LEN);
			new_ent->login[MAX_LOGIN_LEN] = 0;
			size_t key_len;
			bzero(&(new_ent->rsa_key), sizeof(new_ent->rsa_key));
			new_ent->rsa_key.type = KEY_RSA;
			new_ent->rsa_key.ecdsa_nid  = -1;
			if (get_public_keys(login, &(new_ent->rsa_key), new_ent->signer_fp, new_ent->key, &key_len,
								new_ent->fp) == 0) {
				num_recipients++;
			} else {
				error("Unable to retrieve public key information for user %s", login);
				retval = -1;
			}
		} else {
			error("Recipient list is full - cannot add more.");
			retval = -1;
		}
	}

	return retval;
}

/**
 *  Remove a recipient from registered list.
 *
 *  Remove the entry for the specified user from the list of registered recipients. Cannot remove the current
 *  user.
 *
 *  @param login User to remove
 *  @return int 0 if successful, negative number if error
 */
int
remove_recipient(const char * login)
{
	if (initialize() != 0) return -1;

	int retval = -1;

	if (strcmp(login, user_login) == 0) {
		error("Current user (%s) cannot be removed from the recipient list. Ignored.", login);
	} else {
		int i;
		//  Skip the first entry, which is the current user.
		for (i = 1; i < num_recipients; i++) {
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
			error("User %s not found in the recipient list.", login);
		}
	}

	return retval;
}

/**
 *  Reset the registered list.
 *
 *  Empty out the list of registered recipients, except for the first entry, which should be the current
 *  user's entry. That one should always be in the list.
 */
void
reset_recipients()
{
	if (num_recipients >= 1) {
		num_recipients = 1;
	}
}


/* ================================================================================================================
 * Here lie the unit tests for the functions in this file. If you compile this file with TESTING defined, it will
 * include all the tests.
 *
 * One reason for doing it this way is to allow almost all the code in this file to remain static and still have
 * unit tests.
 * ================================================================================================================ */
#ifdef TESTING

#include "regress/unittests/test_helper/test_helper.h"

#include <string.h>
#include <unistd.h>
#include <pwd.h>


/*  Retrieve next packet - read header, then read body specified by header length.  */
static int
get_gpg_message(FILE * infile, gpg_message * msg)
{
	int retval = -1;

	if (get_tag_and_size(infile, &msg->tag, &msg->len) == 0) {
		if (msg->len > 0) {
			u_char * buf = malloc(msg->len);
			int num_read = fread(buf, sizeof(u_char), msg->len, infile);
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
	u_char * h;
	size_t h_len;
	gpg_tag tag;
	ssize_t size;
} tdata;

static void
do_tag_and_size(const tdata * td)
{
	u_char hdr[8];
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

	u_char h0[] = {0x84, 0x00};
	u_char h1[] = {0x88, 0x01};
	u_char h2[] = {0x8d, 0x12, 0x34};
	u_char h3[] = {0x92, 0xfe, 0xdc, 0xba, 0x98};
	u_char h4[] = {0x97};
	u_char h5[] = {0xd1, 0x23};
	u_char h6[] = {0xd2, 0xc1, 0x23};
	u_char h7[] = {0xd3, 0xff, 0x12, 0x34, 0x56, 0x78};
	u_char h8[] = {0xfc, 0xe1};
		
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

	TEST_DONE();
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
	TEST_START("get_and_put_msgs");

	//  Some faux GPG messages
	u_char buf[] = {
		0x84, 0x04, 0x01, 0x23, 0x45, 0x67,
		0xd1, 0x04, 0x01, 0x23, 0x45, 0x67
	};

	u_char h0[] = {0x01, 0x23, 0x45, 0x67};
	u_char * h1 = malloc(256);
	for (int i = 0; i < 256; i++) {
		h1[i] = i;
	}
	u_char * h2 = malloc(4096);
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

	TEST_DONE();
}

static void
test_bignums(void)
{
	TEST_START("bignums");

	static u_char bn1[] = { 0x00, 0x06, 0x23 };
	static u_char bn2[] = { 0x00, 0x08, 0xa5 };
	static u_char bn3[] = { 0x00, 0x15, 0x12, 0x34, 0x56 };
	static u_char bn4[] = {
		0x01, 0x00,
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff
	};


	typedef struct bndata {
		u_char * bndata;
		size_t bndata_len;
		int num_bits;
	} bndata;

	bndata test_item[] = {
		{ bn1, sizeof(bn1), 6 },
		{ bn2, sizeof(bn2), 8 },
		{ bn3, sizeof(bn3), 21 },
		{ bn4, sizeof(bn4), 256 }
	};


	struct sshbuf * bn_buf = sshbuf_new();
	BIGNUM * bn = BN_new();
	for (size_t i = 0; i < sizeof(test_item) / sizeof(bndata); i++) {
		BN_bin2bn(test_item[i].bndata + 2, test_item[i].bndata_len - 2, bn);
		put_bignum(bn_buf, bn);
	}

	u_char tmp[64];
	for (size_t i = 0; i < sizeof(test_item) / sizeof(bndata); i++) {
		int retval = get_bignum(bn_buf, bn);
		ASSERT_INT_EQ(retval, 0);
		ASSERT_INT_EQ(BN_num_bits(bn), test_item[i].num_bits);
		int len = BN_bn2bin(bn, tmp);
		ASSERT_INT_EQ(len, test_item[i].bndata_len - 2);
		ASSERT_INT_EQ(memcmp(tmp, test_item[i].bndata + 2, len), 0);
	}

	sshbuf_free(bn_buf);
	BN_free(bn);

	TEST_DONE();
}

static void
test_s2k(void)
{
	TEST_START("s2k");

	static u_char salt[S2K_SALT_BYTES] = { 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
	const char * pphrase = "ImGumbyAndYouAreNot";

	static u_char expected_key1[AES128_KEY_BYTES] = {
		0x0e, 0xa5, 0x00, 0x1c, 0xce, 0xad, 0x7e, 0xa8, 0xa0, 0x81, 0x38, 0xae, 0xaf, 0x4e, 0x28, 0xd5
	};
	u_char s2k_key1[AES128_KEY_BYTES];

	compute_gpg_s2k_key(pphrase, sizeof(s2k_key1), salt, S2K_ITER_BYTE_COUNT, s2k_key1);
	ASSERT_INT_EQ(memcmp(s2k_key1, expected_key1, sizeof(s2k_key1)), 0);

	//  Second test to handle the case where we need to run multiple hashes to generate enough bits
	//  Note that the first 16 bytes are the same as the previous test - this is to be expected, since the
	//  salt and passphrase are the same, so the first hash is executed identically.
	static u_char expected_key2[48] = {
		0x0e, 0xa5, 0x00, 0x1c, 0xce, 0xad, 0x7e, 0xa8, 0xa0, 0x81, 0x38, 0xae, 0xaf, 0x4e, 0x28, 0xd5,
		0x21, 0xf1, 0xee, 0x4b, 0x02, 0xc0, 0x0f, 0x63, 0x6a, 0x17, 0xbf, 0x62, 0x34, 0x10, 0x26, 0x48,
		0x7b, 0xc6, 0x3f, 0x08, 0x9d, 0xb5, 0x6b, 0x34, 0x70, 0x3b, 0x71, 0xdb, 0x67, 0x92, 0x6f, 0x5f
	};
	u_char s2k_key2[48];

	compute_gpg_s2k_key(pphrase, sizeof(s2k_key2), salt, S2K_ITER_BYTE_COUNT, s2k_key2);
	ASSERT_INT_EQ(memcmp(s2k_key2, expected_key2, sizeof(s2k_key2)), 0);

	TEST_DONE();
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
	test_bignums();
	test_s2k();
}

#endif
