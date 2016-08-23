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

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>
/*
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include "sftp-common.h"
#include "openbsd-compat/openbsd-compat.h"
#include "key.h"
#include "ssherr.h"
#include "cipher.h"
#include "digest.h"
#include "misc.h"
#include "sodium.h"
#include "openssl/opensslconf.h"
#include "openssl/evp.h"
#include "openssl/engine.h"
#include "openssl/sha.h"
#include "openssl/ripemd.h"
*/
#include "log.h"
#include "sshbuf.h"
#include "xmalloc.h"

#include "iron-common.h"
#include "iron-gpg.h"
#include "iron/gpg-internal.h"
#include "iron/gpg-key.h"
#include "iron/gpg-keyfile.h"
#include "iron/gpg-packet.h"
#include "iron/gpg-trustdb.h"
#include "iron/recipient.h"
#include "iron/util.h"



static int      gpg_now;        //  Everything that timestamps a packet during the same "transaction" should
                                //  use this time, so they all get timestamped the same.
static char   * user_login;     //  Stores the login of the user running the process. Set at initialization.

static int      inited = 0;     //  Indicates that the process has initialized everything needed for IronSFTP

/**
 *  Initialize the needful.
 *
 */
int
iron_initialize(void)
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

    gpg_now = (u_int32_t) time(NULL);
    return retval;
}

const char *
iron_user_login(void)
{
    return user_login;
}

u_int32_t
iron_gpg_now(void)
{
    return gpg_now;
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
    u_char * output = malloc(CHUNK_SIZE + 2 * AES_BLOCK_SIZE);
    u_char * input = malloc(CHUNK_SIZE);
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
write_encrypted_data_file(FILE * infile, const char * fname, FILE * outfile, u_char * sym_key)
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

        u_char data_pkt_hdr[128];
        int data_pkt_hdr_len = generate_gpg_literal_data_packet(fname, statstr.st_size, statstr.st_mtime,
                data_pkt_hdr);

        //  Add size of random data prefix and MDC packet and version # prefix
        int data_len = data_pkt_hdr_len + statstr.st_size +
            AES_BLOCK_SIZE + 2 /*prefix*/ + 22 /*MDC*/ + 1 /*version*/;

        //  Start emitting the SEIP packet.
        gpg_packet seipd_pkt;
        generate_gpg_seipd_packet_hdr(data_len, &seipd_pkt);
        retval = put_gpg_packet(outfile, &seipd_pkt);
        sshbuf_free(seipd_pkt.data);
        if (retval == 0) {
            //  From this point, everything is hashed and encrypted. Start with the random prefix bytes, then the
            //  last two bytes repeated.
            u_char input[128];
            u_char output[128];
            randombytes_buf(input, AES_BLOCK_SIZE);
            input[AES_BLOCK_SIZE] = input[AES_BLOCK_SIZE - 2];
            input[AES_BLOCK_SIZE + 1] = input[AES_BLOCK_SIZE - 1];

            u_char * outp = output + hashcrypt(&sha_ctx, &aes_ctx, input, AES_BLOCK_SIZE + 2, output);

            //  Add the header for the Literal Data Packet
            outp += hashcrypt(&sha_ctx, &aes_ctx, data_pkt_hdr, data_pkt_hdr_len, outp);
            fwrite(output, 1, outp - output, outfile);

            int total_read = encrypt_input_file(infile, outfile, &sha_ctx, &aes_ctx);
            if (total_read >= 0) {
                if ((off_t) total_read == statstr.st_size) {
                    retval = write_gpg_mdc_packet(outfile, &sha_ctx, &aes_ctx);
                } else {
                    error("Did not read the complete input file.");
                    retval = -1;
                }
            }
        }

        EVP_CIPHER_CTX_cleanup(&aes_ctx);
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
    if (iron_initialize() != 0) return -1;

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
                    gpg_packet pkesk;
                    generate_gpg_pkesk_packet(recipient_key + i, sym_key_frame, sizeof(sym_key_frame), &pkesk);
                    retval = put_gpg_packet(outfile, &pkesk);
                    sshbuf_free(pkesk.data);
                    pkesk.data = NULL;
                }

                if (retval == 0) {
                    retval = write_encrypted_data_file(infile, fname, outfile, sym_key_frame + 1);
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
    } else {
        error("Unable to read input file \"%s\".", fname);
    }

    return retval;
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
 *  Extract information from start of encrypted data packet.
 *
 *  Read the start of the packet from the file, get the SHA1 hash going, start decrypting, extract
 *  file name.
 *
 *  @param sha_ctx SHA1 hash of decrypted data
 *  @param aes_ctx AES cipher to decrypt data
 *  @param infile File from which to read encrypted data
 *  @param output Place to store decrypted data (at least 528 bytes)
 *  @param fname Place to store name of the file that was encrypted (at least PATH_MAX bytes)
 *  @param num_dec Place to store number of bytes decrypted
 *  @param len Place to store remaining size of encrypted data to process
 *  @param extra Place to store number of bytes of trailing MDC packet that have already been read
 *  @return int Num bytes written to output array, negative number if error
 */
static int
process_enc_data_hdr(SHA_CTX * sha_ctx, EVP_CIPHER_CTX * aes_ctx, FILE * infile,
                     u_char * output, char * fname, int * num_dec, ssize_t * len, int * extra)
{
//  After the header for the SEIPD packet and the one byte version number, there should be encrypted
//  data. The start of this data has 16 bytes of random data, the last two bytes of that data repeated,
//  the header of the literal data packet (at least two bytes), a byte for the data format, a byte for
//  the file name length, the file name (at least one byte), and a four byte timestamp.
#define MIN_ENC_DATA_HDR_SIZE   27

    //  More than enough space to get through all the header stuff and into the encrypted file data.
    u_char input[512];
    size_t num_read = fread(input, 1, sizeof(input), infile);
    if (num_read < MIN_ENC_DATA_HDR_SIZE) {
        error("Input too short - cannot recover data.");
        return -1;
    }

    EVP_DecryptUpdate(aes_ctx, output, num_dec, input, num_read);
    if (*num_dec <= AES_BLOCK_SIZE + 2) {
        error("Decrypted input too short - cannot recover data.");
        return -2;
    }

    //  The first 16 bytes are random data, then the last two bytes of those 16 should be repeated.
    if (output[AES_BLOCK_SIZE] != output[AES_BLOCK_SIZE - 2] ||
            output[AES_BLOCK_SIZE + 1] != output[AES_BLOCK_SIZE - 1]) {
        error("Checksum error in header - cannot recover data.");
        return -3;
    }
    u_char * optr = output + AES_BLOCK_SIZE + 2;

    gpg_tag tag = GPG_TAG_DO_NOT_USE;
    *len = 0;
    int     tag_size_len = extract_gpg_tag_and_size(optr, &tag, len);
    optr += tag_size_len;
    if (tag != GPG_TAG_LITERAL_DATA || *(optr++) != 'b') {  //  We always write literal data in "binary" format)
        error("Unexpected data at start of packet - cannot recover data.");
        return -4;
    }
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
 *  Read encrypted input, write decrypted output.
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
                 u_char * output, int offset, ssize_t len, int extra)
{
    int retval = 0;

    u_char input[CHUNK_SIZE];
    int num_dec;
    int num_read;
    u_char * optr = output + offset;

    while (len > 0) {
        num_read = fread(input, 1, sizeof(input), infile);
        if (ferror(infile)) {
            error("Error reading input file.");
            retval = -1;
            break;
        }
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

        if (fwrite(output, 1, num_dec, outfile) != (size_t) num_dec) {
            error("Error writing output file");
            retval = -1;
            break;
        }
        len -= num_dec;
        SHA1_Update(sha_ctx, output, num_dec);
    }

    //  When we get to here, we should have written the entire decrypted data file, and
    //  optr should point to the start of the MDC packet, if there was part of it in the
    //  last decrypted block. Read the rest of the MDC packet and validate the hash.
    if (retval == 0) {
        retval = -1;

        num_read = fread(input, 1, sizeof(input), infile);
        if (!ferror(infile)) {
            if (extra > 0) {
                memmove(output, optr, extra);
                optr = output + extra;
            }
            EVP_DecryptUpdate(aes_ctx, optr, &num_dec, input, num_read);
            int last_dec;
            EVP_DecryptFinal_ex(aes_ctx, optr + num_dec, &last_dec);
            num_dec += last_dec;
            if (extra + num_dec == GPG_MDC_PKT_LEN) {
                SHA1_Update(sha_ctx, output, 2);
                u_char digest[SHA_DIGEST_LENGTH];
                SHA1_Final(digest, sha_ctx);

                if (memcmp(output + 2, digest, sizeof(digest)) == 0) {
                    retval = 0;
                } else {
                    error("Invalid Modification Detection Code - cannot recover data.");
                }
            } else {
                error("Length of input incorrect - cannot recover data.");
            }
        } else {
            error("Error reading input file.");
        }
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
 *  @return 0 if successful, negative number if errors
 */
int
write_gpg_decrypted_file(const char * fname, char * dec_fname)
{
    if (iron_initialize() != 0) return -1;

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

    const gpg_public_key * pub_keys = get_recipient_keys(iron_user_login());
    if (pub_keys == NULL) {
        error("Unable to retrieve public IronCore keys for user %s.", iron_user_login());
        fclose(infile);
        return -1;
    }

    retval = get_gpg_pkesk_packet(infile, GPG_KEY_ID_FROM_FP(pub_keys->fp), msg, &next_tag, &next_len);
    if (retval == 0) {
        u_char * msg_ptr = msg;
        if (*(msg_ptr++) == GPG_PKALGO_ECDH) {
            const u_char *ephem_pk;
            int ekey_offset = extract_gpg_ephemeral_key(msg_ptr, &ephem_pk);
            if (ekey_offset < 0) {
                fclose(infile);
                return -2;
            }
            msg_ptr += ekey_offset;

            //  If we are actually abole to retrieve what we think is a PKESK packet, chances are good that
            //  this is really a file containing GPG encrypted data. Before we can get further, we need to
            //  retrieve the user's secret key.
            u_char sym_key[AES256_KEY_BYTES];
            int rv = extract_gpg_sym_key(msg_ptr, pub_keys, ephem_pk, sym_key);
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
            u_char output[CHUNK_SIZE + 2 * AES_BLOCK_SIZE];
            u_char seipd_ver = fgetc(infile);
            if (next_tag == GPG_TAG_SEIP_DATA && seipd_ver == GPG_SEIPD_VERSION) {
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
                    char local_fname[PATH_MAX];
                    int rv = process_enc_data_hdr(&sha_ctx, &aes_ctx, infile, output, local_fname, &num_dec,
                                                  &len, &extra);
                    if (rv < 0) {
                        fclose(infile);
                        return -5;
                    }

                    u_char * optr = output + rv;
                    FILE * outfile = open_decrypted_output_file(fname, dec_fname);
                    if (outfile != NULL) {
                        //  Flush remainder of output buffer that is file data. May still be some left that is
                        //  all or part of the MDC packet.
                        fwrite(optr, 1, num_dec, outfile);
                        SHA1_Update(&sha_ctx, optr, num_dec);
                        len -= num_dec;
                        optr += num_dec;

                        retval = process_enc_data(&sha_ctx, &aes_ctx, infile, outfile, output, optr - output,
                                len, extra);

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
