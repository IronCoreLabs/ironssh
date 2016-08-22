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

#include <string.h>
#include <pwd.h>

#include "openssl/rsa.h"
#include "openssl/sha.h"

#include "iron-common.h"
#include "iron-gpg.h"
#include "iron/gpg-internal.h"
#include "iron/util.h"

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
void
iron_hex2str(const u_char * hex, int hex_len, char * str)
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
int
iron_str2hex(const char * str, u_char * hex, int hex_len)
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
void
iron_int_to_buf(int val, u_char * buf)
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
u_int32_t
iron_buf_to_int(const u_char * buf)
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
int
iron_put_bignum(struct sshbuf * buf, const BIGNUM * bignum)
{
    int retval = -1;
    int num_bits = BN_num_bits(bignum);
    int num_bytes = BN_num_bytes(bignum);

    if (sshbuf_put_u16(buf, num_bits) == 0) {
        u_char tmp[2 * GPG_MAX_KEY_SIZE];
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
 *  The first byte of the S-expression needs to not have the high (sign) bit set. If it does, add a 0 byte at
 *  the start.
 *
 *  @param buf Place to write S-expression
 *  @param bstr Byte array
 *  @param bstr_len Num bytes in bstr
 */
void
iron_put_num_sexpr(struct sshbuf * buf, const u_char * bstr, int bstr_len)
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
const char *
iron_get_user_ssh_dir(const char * const login)
{
    /* If the requested login is the current user's login, cache the ssh directory value, since we will
     * probably need it a few times.
     */
    static char curr_ssh_dir[PATH_MAX] = { 0 };

    if (strcmp(login, iron_user_login()) == 0) {
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
 *  Swap order of bytes in one byte array into a second array.
 *
 *  @param src Input byte array
 *  @param dst Place to write reversed byte array (at least len bytes)
 *  @param len Num bytes in src
 */
void
iron_reverse_byte_array(const u_char * src, u_char * dst, unsigned int len) {
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
void
iron_reverse_byte_array_in_place(u_char * arr, unsigned int len) {
    for (unsigned int ct = 0; ct < len / 2; ct++) {
        unsigned int ct2 = len - 1 - ct;
        u_char tmp = arr[ct];
        arr[ct]  = arr[ct2];
        arr[ct2] = tmp;
    }
}

/**
 *  Calculate SHA1 hash of sshbuf contents.
 *
 *  @param buf Buffer to hash
 *  @param hash Place to write computed hash - at least SHA_DIGEST_LENGTH bytes
 */
void
iron_compute_sha1_hash_sshbuf(const struct sshbuf * buf, u_char * hash)
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
void
iron_compute_sha1_hash_chars(const u_char * bstr, int bstr_len, u_char * hash)
{
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, bstr, bstr_len);
    SHA1_Final(hash, &ctx);
}

/**
 *  Simultaneously update a SHA1 hash, a SHA256 hash, and an AES encryption with data buffer.
 *
 *  Given a block of data, add to running SHA1 hash and optionally a SHA256 hash, then AES encrypt the
 *  data and write to output buffer.
 *
 *  @param sha_ctx Running SHA1 hash
 *  @param sig_ctx Running SHA256 hash, or NULL to skip SHA256
 *  @param aes_ctx Running AES encryption of data
 *  @param input Buffer to hash/encrypt
 *  @param size Num bytes in input
 *  @param output Place to write encrypted output generated by AES
 *  @return int Num bytes written to output
 */
int
iron_hashcrypt(SHA_CTX * mdc_ctx, SHA256_CTX * sig_ctx, EVP_CIPHER_CTX * aes_ctx, const u_char * input,
	   	  int size, u_char * output)
{
	int num_written;
	SHA1_Update(mdc_ctx, input, size);
	if (sig_ctx != NULL) {
		SHA256_Update(sig_ctx, input, size);
	}
	if (EVP_EncryptUpdate(aes_ctx, output, &num_written, input, size)) return num_written;
	else return -1;
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
BIGNUM *
iron_compute_rsa_signature(const u_char * digest, size_t digest_len, const Key * key)
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
 *  Check the directory/file name to see if it ends with the .iron sharing suffix.
 *
 *  @param fname Path name to inspect
 *  @return int Offset of suffix in fname, or -1 if fname doesn't end with suffix
 */
int
iron_extension_offset(const char * name)
{
        int retval = -1;
        int offset = strlen(name) - IRON_SECURE_FILE_SUFFIX_LEN;
        if (offset >= 0) {
                if (strcmp(name + offset, IRON_SECURE_FILE_SUFFIX) == 0) {
                        retval = offset;
                }
        }

        return retval;
}
