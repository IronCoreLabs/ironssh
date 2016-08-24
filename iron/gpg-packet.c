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

#include <libgen.h>
#include <string.h>

#include "openssl/rsa.h"

#include "key.h"
#include "log.h"

#include "iron-gpg.h"
#include "iron/gpg-internal.h"
#include "iron/gpg-key.h"
#include "iron/gpg-keyfile.h"
#include "iron/gpg-packet.h"
#include "iron/util.h"


//  Some constants related to the header of a GPG message - the tag byte and length.
#define GPG_TAG_MARKER_BIT      0x80    //  Tag byte should ALWAYS have high bit set
#define GPG_TAG_FORMAT_BIT      0x40    //  Next bit of tag indicates old (0) or new (1) format
#define GPG_TAG_OF_MASK         0x3c    //  In old format, bits 2-5 are tag value
#define GPG_TAG_OF_SHIFT        2       //  In old format, shift of last two bits (lentype) got get tag
#define GPG_TAG_OF_LENTYPE_MASK 0x03    //  In old format, last two bits indicate type of following length
#define GPG_TAG_NF_MASK         0x3f    //  In new format, low 6 bits are tag value
#define GPG_TAG_NF_MASK         0x3f    //  In new format, low 6 bits are tag value
#define GPG_OF_LENTYPE_SHORT    0
#define GPG_OF_LENTYPE_MEDIUM   1
#define GPG_OF_LENTYPE_LONG     2
#define GPG_OF_LENTYPE_INDETERMINATE 3  //  Special size value to indicate length must be determined externally to pkt
#define GPG_OF_LEN_SHORT        1
#define GPG_OF_LEN_MEDIUM       2
#define GPG_OF_LEN_LONG         4
#define GPG_OF_LEN_INDETERMINATE -1     //  Special size value to indicate length must be determined externally to pkt
#define GPG_NF_LEN_THRESHOLD1   0xc0    //  New format lengths shorter than 0xc0 (192) bytes are in one byte
#define GPG_NF_LEN_SHORT        1
#define GPG_NF_LEN_THRESHOLD2   0xe0    //  New format lengths that start with a value between 0xc0 and 0xdf (223)
                                        //      are two bytes long
#define GPG_NF_LEN_MEDIUM       2
#define GPG_NF_LEN_LIMIT_MEDIUM 0x20c0  //  Maximum length that can be encoded into the medium (2-byte) format using
                                        //      that goofy encoding algorithm
#define GPG_NF_LEN_THRESHOLD4   0xff    //  New format lengths that start with a value of 0xff are five bytes
                                        //      long - 0xff is ignored, and next four bytes are length
#define GPG_NF_LEN_LONG         5
#define GPG_NF_LEN_PARTIAL      1

#define GPG_OF_TAG_LIMIT        15      //  Old format tags need to fit into 4 bits in tag byte
#define GPG_NF_TAG_LIMIT        63      //  New format tags need to fit into 6 bits in tag byte



/**
 *  Write packet to file.
 *
 *  @param outfile File to which to write
 *  @param pkt Packet to write
 *  @return int 0 if successful, negative number if error
 */
int
put_gpg_packet(FILE * outfile, const gpg_packet * pkt)
{
    int retval = -1;
    char buf[7];

    int buf_len = generate_gpg_tag_and_size(pkt->tag, pkt->len, buf);
    if (buf_len > 0 && fwrite(buf, sizeof(char), buf_len, outfile) == (size_t) buf_len) {
        const u_char * tmp_ptr = sshbuf_ptr(pkt->data);
        //  We use the length of the sshbuf instead of the len in the header in case someone is calling
        //  this to output the first part of a packet and will generate the remainder of the data later.
        //  This happens with SEIPD packets.
        size_t num_written = fwrite(tmp_ptr, sizeof(u_char), sshbuf_len(pkt->data), outfile);
        if (num_written == sshbuf_len(pkt->data)) {
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
                *size = iron_buf_to_int(buf);
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

    if (len_type <= GPG_TAG_OF_LENTYPE_MASK) {  //  Value is only supposed to be two bits
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
get_gpg_tag_and_size(FILE * infile, gpg_tag * tag, ssize_t * size)
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
int
extract_gpg_tag_and_size(const u_char * buf, gpg_tag * tag, ssize_t * size)
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
int
generate_gpg_tag_and_size(gpg_tag tag, ssize_t size, u_char * buf)
{
    int len = -1;

    if ((int) tag <= GPG_OF_TAG_LIMIT) {
        //  Tag small enough to fit into an old-format tag octet and length.
        buf[0] = GPG_TAG_MARKER_BIT | (tag << GPG_TAG_OF_SHIFT);

        if (size < 0) {
            buf[0] |= GPG_OF_LENTYPE_INDETERMINATE;
            len = 1;        // Only tag byte - no length bytes
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
 *  Generate GPG public key packet.
 *
 *  Given an SSH key, create a GPG Public Key packet with the data from the SSH Key.
 *
 *  ** Currently only handles RSA keys.
 *
 *  @param ssh_key SSH RSA key
 *  @param pkt Place to write packet. Caller should sshbuf_free pkt->data
 */
void
generate_gpg_public_key_packet(const Key * ssh_key, gpg_packet * pkt)
{
    pkt->tag = GPG_TAG_PUBLIC_KEY;
    pkt->data = sshbuf_new();

    sshbuf_put_u8(pkt->data, GPG_KEY_VERSION);
    sshbuf_put_u32(pkt->data, iron_gpg_now());
    sshbuf_put_u8(pkt->data, GPG_PKALGO_RSA_ES);
    iron_put_bignum(pkt->data, ssh_key->rsa->n);
    iron_put_bignum(pkt->data, ssh_key->rsa->e);
    pkt->len = sshbuf_len(pkt->data);
}

/**
 *  Generate GPG Subkey Packet for cv25519 key.
 *
 *  Format a GPG Subkey packet containing a cv25519 public key.
 *
 *  @param pub_key Byte array containing cv25519 public key
 *  @param pk_len Num bytes in pub_key
 *  @param pkt Place to put generated packet. Caller should sshbuf_free pkt->data
 */
void
generate_gpg_curve25519_subkey_packet(const u_char * pub_key, size_t pk_len, gpg_packet * pkt)
{
    pkt->tag = GPG_TAG_PUBLIC_SUBKEY;
    pkt->data = sshbuf_new();

    sshbuf_put_u8(pkt->data, GPG_KEY_VERSION);
    sshbuf_put_u32(pkt->data, iron_gpg_now());
    sshbuf_put_u8(pkt->data, GPG_PKALGO_ECDH);      //  Curve25519 is an instance of ECDH
    generate_gpg_curve25519_pubkey_parms(pub_key, pk_len, pkt->data);
    pkt->len = sshbuf_len(pkt->data);
}

/**
 *  Generate GPG User ID packet.
 *
 *  @param user_id String identifying user (name and <email>, often)
 *  @param pkt Place to write packet. Caller should sshbuf_free pkt->data
 */
void
generate_gpg_user_id_packet(const char * user_id, gpg_packet * pkt)
{
    pkt->tag = GPG_TAG_USERID;
    pkt->data = sshbuf_from(user_id, strlen(user_id));
    pkt->len = sshbuf_len(pkt->data);
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
    sshbuf_put_u16(body, 24);       //  Length of hashed subpackets
    sshbuf_put_u8(body, 5);         //  Length of signature creation time subpacket
    sshbuf_put_u8(body, GPG_SIG_SUBPKT_SIGNATURE_CREATION_TIME);
    sshbuf_put_u32(body, iron_gpg_now());
    sshbuf_put_u8(body, 5);         //  Length of key lifetime subpacket
    sshbuf_put_u8(body, GPG_SIG_SUBPKT_KEY_LIFETIME);
    sshbuf_put_u32(body, 0);            //  Does not expire
    sshbuf_put_u8(body, 5);         //  Length of preferred symmetric algorithm subpacket
    sshbuf_put_u8(body, GPG_SIG_SUBPKT_PREF_SYM_ALGO);
    sshbuf_put_u8(body, GPG_SKALGO_AES256);
    sshbuf_put_u8(body, GPG_SKALGO_AES192);
    sshbuf_put_u8(body, GPG_SKALGO_AES128);
    sshbuf_put_u8(body, 0);         //  No fourth preferred SK algorithm
    sshbuf_put_u8(body, 2);         //  Length of key flags subpacket
    sshbuf_put_u8(body, GPG_SIG_SUBPKT_KEY_FLAGS);
    if (pubkey_tag == GPG_TAG_PUBLIC_KEY) {
        sshbuf_put_u8(body, 0x03);      // Sign + certify
    } else if (pubkey_tag == GPG_TAG_PUBLIC_SUBKEY) {
        sshbuf_put_u8(body, 0x0c);      // encrypt
    } else {
        sshbuf_put_u8(body, 0x00);
    }
    sshbuf_put_u8(body, 2);         //  Length of features subpacket
    sshbuf_put_u8(body, GPG_SIG_SUBPKT_FEATURES);
    sshbuf_put_u8(body, 0x01);          // enabled MDC - integrity protection for encrypted data packets
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
    iron_int_to_buf(len, trailer + 2);
    SHA256_Update(ctx, trailer, 6);
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
compute_signature_hash(const gpg_packet * pubkey_pkt, const gpg_packet * uid_pkt, const gpg_packet * sig_pkt,
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
    int len = generate_gpg_tag_and_size(pubkey_pkt->tag, pubkey_pkt->len, buf);
    SHA256_Update(&ctx, buf, len);
    SHA256_Update(&ctx, sshbuf_ptr(pubkey_pkt->data), sshbuf_len(pubkey_pkt->data));

    /* Next, do the same with the UID packet, if there is one. Need to fiddle with the tag/length, because when
     * GPG hashes it, it expands the length out to four bytes instead of one. Grr.
     */
    if (uid_pkt != NULL) {
        buf[0] = 0xb4;   //  uid_pkt->tag converted to a tag byte
        iron_int_to_buf(uid_pkt->len, buf + 1);
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
 *  @param pkt Place to write generated packet. Caller should sshbuf_free pkt->data
 */
void
generate_gpg_pk_uid_signature_packet(const gpg_packet * pubkey_pkt, const gpg_packet * uid_pkt,
                                     const Key * key, int sig_class, const u_char * key_id,
                                     gpg_packet * pkt)
{
    pkt->tag = GPG_TAG_SIGNATURE;
    pkt->data = sshbuf_new();

    populate_signature_header(pkt->data, sig_class, pubkey_pkt->tag);

    u_char hash[SHA256_DIGEST_LENGTH];
    compute_signature_hash(pubkey_pkt, uid_pkt, pkt, hash);

    /* Add the unhashed subpackets to the signature packet now. Currently, just the issuer subpacket. */
    sshbuf_put_u16(pkt->data, GPG_KEY_ID_LEN + 2);  //  Length of unhashed subpackets
    sshbuf_put_u8(pkt->data, GPG_KEY_ID_LEN + 1);   //  Length of issuer subpacket
    sshbuf_put_u8(pkt->data, GPG_SIG_SUBPKT_ISSUER);
    sshbuf_put(pkt->data, key_id, GPG_KEY_ID_LEN);

    /* Tack on the first two bytes of the hash value, for error detection. */
    sshbuf_put_u8(pkt->data, hash[0]);
    sshbuf_put_u8(pkt->data, hash[1]);

    /* Now compute the RSA signature of the hash - m^d mod n, where m is the message (the hash), d is the
     * private key, and n is the modulus. This MPI goes into the signature packet (with the normal two-octet
     * length prefix).
     */
    BIGNUM * sig = iron_compute_rsa_signature(hash, SHA256_DIGEST_LENGTH, key);
    iron_put_bignum(pkt->data, sig);
    BN_clear_free(sig);
    pkt->len = sshbuf_len(pkt->data);
}

/**
 *  Generate a GPG Trust packet.
 *
 *  @param pkt Place to write generated packet
 */
void
generate_gpg_trust_packet(gpg_packet * pkt)
{
    pkt->tag = GPG_TAG_TRUST;
    pkt->data = sshbuf_new();
    pkt->len = 2;
    sshbuf_put_u8(pkt->data, 0);
    sshbuf_put_u8(pkt->data, 3);
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
 *  @param pkt Place to write generated packet
 *  @return 0 if successful, negative number if error
 */
int
generate_gpg_pkesk_packet(const gpg_public_key * key, u_char * sym_key_frame, int frame_len,
                          gpg_packet * pkt)
{
    int retval = -1;

    pkt->tag = GPG_TAG_PKESK;
    pkt->data = sshbuf_new();

    sshbuf_put_u8(pkt->data, GPG_PKESK_VERSION);
    sshbuf_put(pkt->data, key->fp + (GPG_KEY_FP_LEN - GPG_KEY_ID_LEN), GPG_KEY_ID_LEN);
    sshbuf_put_u8(pkt->data, GPG_PKALGO_ECDH);      //  Algorithm used to encrypt symmetric key

    //  We are going to encrypt the sym. key frame using AES128-WRAP. This requires that the frame be a multiple
    //  of the block size (8), which it is. The encryption will add one more block on the end of the encrypted
    //  data.
    //  Also leave an extra byte at the beginning to hold the encrypted frame length.
    u_char ephem_pk[crypto_box_PUBLICKEYBYTES + 1];
    u_char * enc_frame = malloc(frame_len + 2 * AES_WRAP_BLOCK_SIZE + 1);
    int enc_frame_len = encrypt_gpg_key_frame(sym_key_frame, frame_len, key, enc_frame + 1, ephem_pk);
    if (enc_frame_len > 0) {
        *enc_frame = (u_char) enc_frame_len;
        enc_frame_len++;

        //  Write the ephemeral PK first, prefixed with the two-byte length in bits.
        //  Then write the encrypted frame without a length prefix.
        sshbuf_put_u16(pkt->data, crypto_box_PUBLICKEYBYTES * 8 + 7);
        sshbuf_put(pkt->data, ephem_pk, sizeof(ephem_pk));
        sshbuf_put(pkt->data, enc_frame, enc_frame_len);
        pkt->len = sshbuf_len(pkt->data);
        free(enc_frame);
        retval = 0;
    }

    return retval;
}

/**
 *  Generate the start of the SEIPD packet
 *
 *  Creates the header for the Symmetrically Encrypted and Integrity Protected Data (SEIPD) packet.
 *  The caller should precalculate the size of the data that will follow the first part of the
 *  packet in the body and will be responsible for generating that data after this header is output.
 */
void
generate_gpg_seipd_packet_hdr(int data_len, gpg_packet * pkt)
{
    pkt->tag = GPG_TAG_SEIP_DATA;
    pkt->data = sshbuf_new();
    sshbuf_put_u8(pkt->data, GPG_SEIPD_VERSION);
    pkt->len = data_len + sshbuf_len(pkt->data);
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
int
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
    int literal_hdr_len = generate_gpg_tag_and_size(GPG_TAG_LITERAL_DATA, data_len, literal_hdr);

    u_char * dptr = data_pkt_hdr;
    memcpy(dptr, literal_hdr, literal_hdr_len);
    dptr += literal_hdr_len;
    *(dptr++) = 'b';                //  Indicates "binary" data, no CR-LF conversion
    *(dptr++) = strlen(base_name);  //  Precede name by its length, in one byte
    strcpy(dptr, base_name);
    dptr += strlen(base_name);
    iron_int_to_buf(mod_time, dptr);
    dptr += 4;
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
int
write_gpg_mdc_packet(FILE * outfile, SHA_CTX * sha_ctx, EVP_CIPHER_CTX * aes_ctx)
{
    int retval = -1;
    //  We hash the header of the MDC packet into the MDC hash, then the hash is finalized and becomes
    //  the body of the MDC packet. The MDC packet is encrypted, and the AES encryption is finalized
    //  and output.
    u_char input[SHA_DIGEST_LENGTH + 2];
    input[0] = 0xd3;        //  The formatted tag of the Modification Detection Code (MDC) packet
    input[1] = 0x14;        //  The length of the MDC packet

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
 *  @return gpg_packet containing packet, or NULL if error. Caller should sshbuf_free pkt->data, free pkt
 */
gpg_packet *
get_gpg_pub_key_packet(FILE * infile)
{
    gpg_tag tag = GPG_TAG_DO_NOT_USE;
    size_t len;

    gpg_packet * pkt = NULL;
    get_gpg_tag_and_size(infile, &tag, &len);
    if (tag == GPG_TAG_PUBLIC_KEY) {
        u_char * key = malloc(len);
        if (fread(key, 1, len, infile) == (size_t) len) {
            pkt = malloc(sizeof(gpg_packet));
            pkt->tag = tag;
            pkt->len = len;
            pkt->data = sshbuf_from(key, len);
        } else {
            error("Unable to read full public key packet from file.");
            free(key);
        }
    }

    return pkt;
}

/**
 *  Read subkey packet from file.
 *
 *  @param infile File from which to read
 *  @return gpg_packet containing packet, or NULL if error. Caller should sshbuf_free pkt->data, free pkt
 */
gpg_packet *
get_gpg_curve25519_key_packet(FILE * infile)
{
    gpg_tag tag = GPG_TAG_DO_NOT_USE;
    size_t len;

    gpg_packet * pkt = NULL;
    u_char * subkey = NULL;

    do {
        get_gpg_tag_and_size(infile, &tag, &len);
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

    if (tag == GPG_TAG_PUBLIC_SUBKEY && subkey != NULL) {
        //  Make sure it's a curve22519 subkey. Shouldn't be anything else in the file, but just make sure.
        if (!gpg_packet_is_curve25519_key(subkey, len)) {
            //  Nope - different subkey. Throw the packet away and try again.
            free(subkey);
            pkt = get_gpg_curve25519_key_packet(infile);
        } else {
            pkt = malloc(sizeof(gpg_packet));
            pkt->tag = tag;
            pkt->len = len;
            pkt->data = sshbuf_from(subkey, len);
        }
    }

    return pkt;
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
 *  @param pkt Place to write PKESK packet if found
 *  @param next_tag Tag of next packet found after last PKESK packet
 *  @param next_len Length of next packet found after last PKESK packet
 *  @return int 0 if successful, negative number if error
*/
int
get_gpg_pkesk_packet(FILE * infile, const char * key_id, u_char * msg, gpg_tag * next_tag, int * next_len)
{
    int retval = IRON_ERR_NOT_FOR_USER;

    *next_tag = GPG_TAG_DO_NOT_USE;
    *next_len = -1;
    gpg_tag tag;
    size_t len;

    if (get_gpg_tag_and_size(infile, &tag, &len) != 0) {
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

        if (get_gpg_tag_and_size(infile, &tag, &len) != 0) {
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

//  The OPS packet has a fixed length - one byte each for the version, sig class, hash algo, PK
//  algo, and last flag, and 8 bytes for the key ID.  Total of 13 bytes.
#define ONE_PASS_SIG_LEN    13

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
int
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
    if (*(ptr++) != 1) return -6;           //  Last OPS flag should always be set

    return ONE_PASS_SIG_LEN;
}

/**
 *  Generate a GPG One Pass Signature packet.
 *
 *  @param key_id ID of the RSA key that will be signing the following data.
 *  @param msg Place to write generated packet
 */
void
generate_gpg_one_pass_signature_packet(const u_char * key_id, gpg_packet * ops_pkt)
{
    ops_pkt->tag = GPG_TAG_ONE_PASS_SIGNATURE;
    ops_pkt->data = sshbuf_new();
    sshbuf_put_u8(ops_pkt->data, GPG_OPS_VERSION);
    sshbuf_put_u8(ops_pkt->data, GPG_SIGCLASS_BINARY_DOC);
    sshbuf_put_u8(ops_pkt->data, GPG_HASHALGO_SHA256);
    sshbuf_put_u8(ops_pkt->data, GPG_PKALGO_RSA_ES);
    sshbuf_put(ops_pkt->data, key_id, GPG_KEY_ID_LEN);
    sshbuf_put_u8(ops_pkt->data, 1);        //  Last flag - we always include just one signature
    ops_pkt->len = sshbuf_len(ops_pkt->data);
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
void
generate_gpg_data_signature_packet(const Key * rsa_key, const u_char * key_id, gpg_packet * sig_pkt)
{
    sig_pkt->tag = GPG_TAG_SIGNATURE;
    sig_pkt->data = sshbuf_new();
    sshbuf_put_u8(sig_pkt->data, GPG_SIG_VERSION);
    sshbuf_put_u8(sig_pkt->data, GPG_SIGCLASS_BINARY_DOC);
    sshbuf_put_u8(sig_pkt->data, GPG_PKALGO_RSA_ES);
    sshbuf_put_u8(sig_pkt->data, GPG_HASHALGO_SHA256);
    sshbuf_put_u16(sig_pkt->data, 6);               //  Length of hashed subpackets
    sshbuf_put_u8(sig_pkt->data, 5);                //  Length of signature creation time subpacket
    sshbuf_put_u8(sig_pkt->data, GPG_SIG_SUBPKT_SIGNATURE_CREATION_TIME);
    sshbuf_put_u32(sig_pkt->data, iron_gpg_now());
    sshbuf_put_u16(sig_pkt->data, GPG_KEY_ID_LEN + 2);  //  Length of unhashed subpackets
    sshbuf_put_u8(sig_pkt->data, GPG_KEY_ID_LEN + 1);   //  Length of issuer subpacket
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
 *  @param sig_ctx Running hash that will be signed to generate signature
 *  @param rsa_key RSA signing key (will be populated with secret params if it isn't already)
 *  @param sig_pkt Signature packet with everything populated except the signature (including the length)
 */
int
finalize_gpg_data_signature_packet(SHA256_CTX * sig_ctx, Key * rsa_key, gpg_packet * sig_pkt)
{
    int retval = -1;

    //  Determine the length of the signature packet through the hashed data section. The body starts
    //  with four octets (version, signature class, PK algorithm, and hash algorithm), then the hashed
    //  subpacket length.
    const u_char * ptr = sshbuf_ptr(sig_pkt->data) + 4;
    int len = (*ptr << 8) + *(ptr + 1);
    len += 6;       //  For the initial bytes, plus the two-byte hashed subpacket length

    SHA256_Update(sig_ctx, sshbuf_ptr(sig_pkt->data), len);
    add_signature_trailer(sig_ctx, len);

    u_char sig_hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(sig_hash, sig_ctx);

    //  The first two bytes of the hash are copied into the signature to allow a quick check for corruption
    //  before actually verifying the signature.
    sshbuf_put_u8(sig_pkt->data, sig_hash[0]);
    sshbuf_put_u8(sig_pkt->data, sig_hash[1]);

    if (get_gpg_secret_signing_key(rsa_key) == 0) {
        BIGNUM * sig = iron_compute_rsa_signature(sig_hash, SHA256_DIGEST_LENGTH, rsa_key);
        iron_put_bignum(sig_pkt->data, sig);
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
int
process_data_signature_packet(const u_char * dec_buf, int buf_len, SHA256_CTX * sig_ctx, const u_char * rsa_key_id)
{
    gpg_tag tag;
    size_t len;
    int sig_hdr_len = extract_gpg_tag_and_size(dec_buf, &tag, &len);
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
    // u_int32_t create_ts = iron_buf_to_int(dptr);  Not currently using, so just skip over.
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
    iron_hex2str(key_id, GPG_KEY_ID_LEN, hex_id);

    //  Quick check of the first two bytes of the hash.
    if (*dptr != hash[0] || *(dptr + 1) != hash[1]) return -12;
    dptr += 2;

    const gpg_public_key * signer_keys = iron_get_recipient_keys_by_key_id(key_id);
    if (signer_keys != NULL) {
        int sig_len = (*dptr << 8) + *(dptr + 1);   //  Size in bits
        dptr += 2;
        sig_len = (sig_len + 7) / 8;            //  Convert to bytes

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

