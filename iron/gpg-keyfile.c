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

#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>

#include "openssl/bn.h"
#include "openssl/engine.h"
#include "openssl/evp.h"
#include "openssl/sha.h"

//#include "authfd.h"
#include "authfile.h"
#include "log.h"
#include "misc.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "xmalloc.h"

#include "iron-gpg.h"
#include "iron/gpg-internal.h"
#include "iron/gpg-key.h"
#include "iron/gpg-keyfile.h"
#include "iron/gpg-packet.h"
#include "iron/gpg-trustdb.h"
#include "iron/util.h"


#define SSH_KEY_FNAME           "id_rsa"
#define SSH_KEY_PUB_EXT         ".pub"
#define GPG_PUBLIC_KEY_FNAME    "pubring.gpg"
#define GPG_SECKEY_SUBDIR       "private-keys-v1.d/"
#define IRON_PUBKEY_LOCAL_FNAME "ironpubkey"    //  Name of the file when it is created in ~/.ssh
#define IRON_PUBKEY_SUBDIR      "pubkeys/"      //  Name of the subdir of ~/.ssh that holds other users' public keys
#define IRON_PUBKEYIDX_SUBDIR   "pubkeyidx/"    //  Name of the subdir of ~/.ssh that holds index of pubkeys by
                                                //      key ID

#define GPG_MAX_UID_LEN         128     //  Max # bytes for a user ID / comment on a public SSH key
#define MAX_PASSPHRASE_RETRIES  3       //  Number of times user is prompted to enter passphrase to access SSH key
#define MAX_IDX_LINE_LEN        256     //  Room for "iron-cv25519: <user>@<host>


/**
 *  Open a file containing a secret key.
 *
 *  File should be in ~/.ssh/ironcore/private-keys-v1.d/. The file is named by appending ".key" to the keygrip.
 *
 *  @param mode Mode string to use for fopen (e.g. "r", "w+")
 *  @param hexgrip Hexadecimal string representation of keygrip computed for key
 *  @return FILE * pointer to file opened is specified mode, or NULL if error
 */
static FILE *
open_seckey_file(const char * mode, const char * hexgrip)
{
    char file_name[PATH_MAX];
    snprintf(file_name, sizeof(file_name), "%s%s%s.key", iron_user_ironcore_dir(), GPG_SECKEY_SUBDIR, hexgrip);
    FILE * infile = fopen(file_name, mode);
    if (infile == NULL) {
        error("Could not open secure key file %s - %s.", file_name, strerror(errno));
    }

    return infile;
}

/**
 *  Open the file containing the RSA secret key
 *
 *  Compute keygrip of RSA public key, convert to hex string, and open the secret key file.
 *
 *  @param mode Mode string to use for fopen (e.g. "r", "w+")
 *  @param rsa_key RSA key (only need public portion)
 *  @return FILE * File containing RSA secret key, opened in specified mode
 */
static FILE *
open_rsa_seckey_file(const char * mode, const Key * rsa_key)
{
    u_char keygrip[SHA_DIGEST_LENGTH];
    char hexgrip [2 * SHA_DIGEST_LENGTH + 1];

    generate_gpg_rsa_keygrip(rsa_key, keygrip);
    iron_hex2str(keygrip, sizeof(keygrip), hexgrip);

    return open_seckey_file(mode, hexgrip);
}

/**
 *  Open the file containing the cv25519 secret key
 *
 *  Compute keygrip of cv25519 public key, convert to hex string, and open the secret key file.
 *
 *  @param mode String specifying mode for fopen()
 *  @param q Cv25519 public key
 *  @param q_len Num bytes in q
 *  @return FILE * File containing cv25519 secret key, opened for in specified mode
 */
static FILE *
open_curve25519_seckey_file(const char * mode, const u_char * q, int q_len)
{
    u_char keygrip[SHA_DIGEST_LENGTH];
    char hexgrip [2 * SHA_DIGEST_LENGTH + 1];

    generate_gpg_curve25519_keygrip(q, q_len, keygrip);
    iron_hex2str(keygrip, sizeof(keygrip), hexgrip);

    return open_seckey_file(mode, hexgrip);
}

/**
 *  Copy one of the SSH key files to a .iron backup copy.
 *
 *  Caller can specify an empty extension, "", to copy the secret key file, or the public extension,
 *  SSH_KEY_PUB_EXT, to copy the public key file.
 *
 *  It is an error if the destination file already exists.
 *
 *  @param ext extension for key file
 *  @return int 0 if copy successful, negative number if error
 */
static int
copy_ssh_key_file(const char * ext)
{
    int retval = -1;
    char cp_cmd[2 * PATH_MAX + 4];   //  Room for "cp " and two file names, space-separated, with NULL term.

    char ssh_key_file[PATH_MAX];
    snprintf(ssh_key_file, PATH_MAX, "%s%s%s", iron_user_ssh_dir(), SSH_KEY_FNAME, ext);

    if (access(ssh_key_file, F_OK) == 0) {
        char iron_key_file[PATH_MAX];
        snprintf(iron_key_file, PATH_MAX, "%s%s%s", iron_user_ironcore_dir(), SSH_KEY_FNAME, ext);

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
 *  @return int 0 if copy successful, negative number if error
 */
static int
copy_ssh_key_files(void)
{
    int retval = -1;

    if (copy_ssh_key_file("") == 0) {
        if (copy_ssh_key_file(SSH_KEY_PUB_EXT) == 0) {
            retval = 0;
        }
    }

    return retval;
}

/**
 *  Generate path of pubkey file for the current user
 *
 *  Helper function to generate the path. This will be ~/.ssh/ironcore/ironpubkey
 *
 *  param @login User for whom to fetch the path
 *  return const char * pointer to path - static buffer, so copy the path before calling again
 */
const char *
iron_user_pubkey_file(void)
{
    static char fname[PATH_MAX];
    snprintf(fname, PATH_MAX, "%s%s", iron_user_ironcore_dir(), IRON_PUBKEY_LOCAL_FNAME);
    return fname;
}

/**
 *  Generate path of pubkey file for the specified login
 *
 *  Helper function to generate the path. This will be ~/.ssh/pubkeys/ironpubkey.<login>.
 *
 *  param @login User for whom to fetch the path
 *  return const char * pointer to path - static buffer, so copy the path before calling again
 */
const char *
iron_pubkey_file(const char * login)
{
    static char fname[PATH_MAX];
    snprintf(fname, PATH_MAX, "%s%s%s@%s", iron_user_ironcore_dir(), IRON_PUBKEY_SUBDIR, 
             login, iron_host());
    return fname;
}

/**
 *  Read login's ~/.ironpubkey file.
 *
 *  Retrieve the IronCore public key entries from the specified login's .ironpubkey file.
 *
 *  @param login User whose key info to retrieve
 *  @param rsa_key Place to write public portion of RSA key from .ironpubkey (at least GPG_MAX_KEY_SIZE bytes)
 *  @param rsa_key_len Place to write num bytes in rsa_key
 *  @param cv25519_key Place to write public portion of Curve25519 key (at least crypto_box_SECRETKEYBYTES bytes)
 *  @param cv25519_key_len Place to write num bytes in cv25519_key
 *  @param rsa_fp Place to write fingerprint of RSA key (at least GPG_KEY_FP_LEN bytes)
 *  @param cv25519_fp Place to write fingerprint of Curve25519 key (at least GPG_KEY_FP_LEN bytes)
 *  @return int 0 if successful, negative number if error
 */
static int
read_pubkey_file(const char * login, Key * rsa_key, u_char * rsa_fp, u_char * cv25519_key,
                 size_t * cv25519_key_len, u_char * cv25519_fp)
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

    FILE * infile = fopen(iron_pubkey_file(login), "r");
    if (infile != NULL) {
        retval = 0;
        char line[3000];
        while (fgets(line, sizeof(line), infile)) {
            char * lptr = line;
            char * token;
            if (strncmp(line, "iron-rsa:", 9) == 0) {
                token = strsep(&lptr, " ");     // Skip initial "iron-rsa: "
                token = strsep(&lptr, " ");     // Next string should be the n value
                if (rsa_key != NULL) {
                    u_char tval[GPG_MAX_KEY_SIZE];
                    int tlen = iron_str2hex(token, tval, GPG_MAX_KEY_SIZE);

                    if (tlen > 0) {
                        rsa_key->rsa = RSA_new();
                        rsa_key->rsa->n = BN_new();
                        BN_bin2bn(tval, tlen, rsa_key->rsa->n);
                        token = strsep(&lptr, " ");     // Next string should be the e value
                        int tlen = iron_str2hex(token, tval, GPG_MAX_KEY_SIZE);
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
                    token = strsep(&lptr, " ");     // Skip to the e value
                }
                token = strsep(&lptr, " ");         // Move to the fp, then strip the trailing \n
                if (rsa_fp != NULL) {
                    lptr = token;
                    strsep(&lptr, " \n");           // Strip the trailing \n or any space
                    int fp_len = iron_str2hex(token, rsa_fp, GPG_KEY_FP_LEN);
                    if (fp_len != GPG_KEY_FP_LEN) {
                        retval = -1;
                        break;
                    }
                }
            } else if (strncmp(line, "iron-cv25519:", 13) == 0) {
                token = strsep(&lptr, " ");     // Skip initial "iron-cv25519: "
                token = strsep(&lptr, " ");
                if (cv25519_key != NULL) {
                    int klen = iron_str2hex(token, cv25519_key, crypto_box_SECRETKEYBYTES);
                    if (klen >= 0) {
                        *cv25519_key_len = klen;
                    } else {
                        retval = -1;
                        break;
                    }
                }
                token = strsep(&lptr, " ");
                if (rsa_fp != NULL) {
                    lptr = token;
                    strsep(&lptr, " \n");           // Strip the trailing \n or any space
                    if (iron_str2hex(token, cv25519_fp, GPG_KEY_FP_LEN) != GPG_KEY_FP_LEN) {
                        retval = -1;
                        break;
                    }
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
    }

    return retval;
}

/**
 *  Write a line to the user's .ironpubkey file containing specified RSA key info.
 *
 *  Write the key name, public key n, public key e, fingerprint, and UID in one line to the file.
 *  Writes the key name as "iron-rsa".
 *
 *  @param outfile File to which to write line
 *  @param key RSA key to write as two hex strings (n and e)
 *  @param fp Byte array containing key fingerprint. Converted to hax string
 *  @return int 0 if successful, negative number if error
 */
static int
write_rsa_key_to_pubkey(FILE * outfile, const Key * rsa_key, const u_char * fp)
{
    int retval = -1;

    u_char pval[GPG_MAX_KEY_SIZE];
    int plen;
    u_char tmp[2 * GPG_MAX_KEY_SIZE + 1];
    plen = BN_bn2bin(rsa_key->rsa->n, pval);
    iron_hex2str(pval, plen, tmp);
    if (fprintf(outfile, "iron-rsa: %s ", tmp) > 0) {
        plen = BN_bn2bin(rsa_key->rsa->e, pval);
        iron_hex2str(pval, plen, tmp);
        fprintf(outfile, "%s ", tmp);
        iron_hex2str(fp, GPG_KEY_FP_LEN, tmp);
        if (fprintf(outfile, "%s\n", tmp) > 0) {
            retval = 0;
        }
    }
    return retval;
}

/**
 *  Write a line to the user's .ironpubkey file containing specified key info.
 *
 *  Write the key name, public key, fingerprint, and UID in one line to the file.
 *
 *  @param outfile File to which to write line
 *  @param key_name Name used to identify key (e.g. "rsa", "cv25519"). Will be prefixed by "iron-"
 *  @param key Public key to write as hex string
 *  @param len Num bytes in key
 *  @param fp Byte array containing key fingerprint. Converted to hax string
 *  @return int 0 if successful, negative number if error
 */
static int
write_key_to_pubkey(FILE * outfile, const char * key_name, const u_char * pub_key, int len,
                    const u_char * fp)
{
    int retval = -1;

    u_char tmp[2 * GPG_MAX_KEY_SIZE + 1];
    iron_hex2str(pub_key, len, tmp);
    if (fprintf(outfile, "iron-%s: %s ", key_name, tmp) > 0) {
        iron_hex2str(fp, GPG_KEY_FP_LEN, tmp);
        if (fprintf(outfile, "%s\n", tmp) > 0) {
            retval = 0;
        }
    }
    return retval;
}

/**
 *  Write RSA and cv25519 key entries to ironpubkey file for current user login.
 *
 *  Creates ~/.ssh/ironpubkey, then write lines for the RSA key and the cv25519 key.
 *  If file already exists, it is overwritten.
 *
 *  @param rsa_key RSA key to write to file (only need public params n and e populated)
 *  @param subkey Public cv25519 key
 *  @param key_fp Byte array containing fingerprint for RSA key
 *  @param subkey_fp Byte array containing fingerprint for cv25519 key
 *  @return int 0 if successful, negative number if error
 */
static int
write_pubkey_file(Key * rsa_key, const u_char * key_fp, const u_char * subkey,
                  const u_char * subkey_fp)
{
    int retval = -1;

    FILE * outfile = fopen(iron_user_pubkey_file(), "w");
    if (outfile != NULL) {
        if (write_rsa_key_to_pubkey(outfile, rsa_key, key_fp) == 0) {
            if (write_key_to_pubkey(outfile, "cv25519", subkey, crypto_box_PUBLICKEYBYTES, subkey_fp) == 0) {
                fchmod(fileno(outfile), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
                fclose(outfile);
                retval = 0;
            }
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
 *  @param prompt String to display to user before reading passphrase ("" to suppress prompt and use no passphrase)
 *  @param key Place to write SSH key read from file.  Caller should sshkey_free
 *  @returns int 0 if successful, negative number if error
 */
int
iron_retrieve_ssh_private_key(const char * prompt, Key ** key)
{
    int retval = -1;

    char ssh_key_file[PATH_MAX];
    snprintf(ssh_key_file, PATH_MAX, "%s%s", iron_user_ironcore_dir(), SSH_KEY_FNAME);

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
 *  public key parameters were fetched along with private key parameters by iron_retrieve_ssh_private_key.
 *
 *  @param comment Place to write comment string read from file. Caller should free
 *  @returns int 0 if successful, negative number if error
 */
static int
retrieve_ssh_public_key(char ** comment)
{
    int retval = -1;

    char ssh_key_file[PATH_MAX];
    snprintf(ssh_key_file, PATH_MAX, "%s%s%s", iron_user_ironcore_dir(), SSH_KEY_FNAME, SSH_KEY_PUB_EXT);

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
 *  @param key Place to write pointer to key read from file. Caller should sshkey_free
 *  @param comment Place to write pointer to comment read from public key file. Caller should free
 */
static int
retrieve_ssh_key(Key ** key, char ** comment)
{
    int retval = iron_retrieve_ssh_private_key("Enter passphrase for SSH key file: ", key);

    //  If we succeeded in reading the private key, read the public key to get the comment field,
    //  which will typically be the user's identification (i.e. email address)
    if (retval == 0) {
        retval = retrieve_ssh_public_key(comment);
    }

    return retval;
}

/**
 *  Retrieve public part of signing and encryption key pairs for specified login.
 *
 *  If the login is not the current user, attempt to read the public parts of the signing (RSA) key and
 *  encryption (cv25519) keys from the specified login's ~/.ironpubkey file.
 *  For the current login, read the public RSA key and encryption subkey for the login from the 
 *  ~<login>/.ssh/pubkey.gpg file.
 *
 *  @param login Name of the user for whom to find the key
 *  @param key Place to put public portion of Curve25519 key (at least crypto_box_PUBLICKEYBYTES bytes)
 *  @param key_len Place to put num bytes in key
 *  @param fp Place to put fingerprint of Curve25519 key (at least GPG_KEY_FP_LEN bytes)
 *  @param rsa_key Place to put public portion of RSA key
 *  @param rsa_fp Place to put fingerprint of RSA key (at least GPG_KEY_FP_LEN bytes)
 *  @return int 0 if successful, negative number if error
 */
int
get_gpg_public_keys(const char * login, Key * rsa_key, u_char * rsa_fp, u_char * key,
                    size_t * key_len, u_char * fp)
{
    int retval = -1;
    if (strcmp(login, iron_user_login()) != 0) {
        retval = read_pubkey_file(login, rsa_key, rsa_fp, key, key_len, fp);
    } else {
        //  Fetch current login's keys from pubring.gpg
        char key_file_name[PATH_MAX];
        FILE * key_file;

        snprintf(key_file_name, PATH_MAX, "%s%s", iron_user_ironcore_dir(), GPG_PUBLIC_KEY_FNAME);
        key_file = fopen(key_file_name, "r");
        if (key_file != NULL) {
            retval = 0;

            gpg_packet * pubkey_pkt = get_gpg_pub_key_packet(key_file);
            if (pubkey_pkt != NULL) {
                compute_gpg_key_fingerprint(pubkey_pkt, rsa_fp);
                retval = extract_gpg_rsa_pubkey(pubkey_pkt->data, rsa_key);
                sshbuf_free(pubkey_pkt->data);
                free(pubkey_pkt);
            } else {
                retval = -1;
            }
            if (retval == 0) {
                gpg_packet * subkey_pkt = get_gpg_curve25519_key_packet(key_file);
                if (subkey_pkt != NULL) {
                    const u_char * key_ptr = sshbuf_ptr(subkey_pkt->data) + get_gpg_curve25519_key_offset();
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
 *  Write GPG pubring.gpg file.
 *
 *  Assemble the packets for the user's public RSA key, UID, signature, public cv25519 subkey, UID, and
 *  signature into a pubring.gpg file in user's ~/ironcore/.ssh directory.
 *
 *  @param ssh_key User's SSH RSA key
 *  @param pub_subkey User's cv25519 public key
 *  @param uid String identifying user (name <emailaddr>, typically)
 *  @param key_fp Place to write fingerprint of the public RSA key. (At least GPG_KEY_FP_LEN bytes)
 *  @param subkey_fp Place to write fingerprint of the public cv25519 key. (At least GPG_KEY_FP_LEN bytes)
 *  @return int 0 if successful, negative number if error
 */
static int
write_public_key_file(const Key * ssh_key, const u_char * pub_subkey, const char * uid, u_char * key_fp,
                      u_char * subkey_fp)
{
    int retval = -1;
    gpg_packet public_key_pkt;
    gpg_packet user_id_pkt;
    gpg_packet sig_pkt;
    gpg_packet trust_pkt;

    char file_name[PATH_MAX];
    snprintf(file_name, PATH_MAX, "%s%s", iron_user_ironcore_dir(), GPG_PUBLIC_KEY_FNAME);
    FILE * pub_file = fopen(file_name, "w");
    if (pub_file == NULL) {
        error("Could not open %s to write public key data - %s.", file_name, strerror(errno));
        return -1;
    }
    fchmod(fileno(pub_file), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    generate_gpg_public_key_packet(ssh_key, &public_key_pkt);
    compute_gpg_key_fingerprint(&public_key_pkt, key_fp);
    u_char * key_id = GPG_KEY_ID_FROM_FP(key_fp);

    generate_gpg_user_id_packet(uid, &user_id_pkt);
    generate_gpg_pk_uid_signature_packet(&public_key_pkt, &user_id_pkt, ssh_key, GPG_SIGCLASS_POSITIVE_CERT,
                                         key_id, &sig_pkt);
    generate_gpg_trust_packet(&trust_pkt);

    retval = put_gpg_packet(pub_file, &public_key_pkt);

    if (retval == 0) {
        retval = put_gpg_packet(pub_file, &user_id_pkt);
        if (retval == 0) {
            retval = put_gpg_packet(pub_file, &sig_pkt);
            if (retval == 0) {
                retval = put_gpg_packet(pub_file, &trust_pkt);
            }
        }
    }
    sshbuf_free(public_key_pkt.data);
    sshbuf_free(user_id_pkt.data);
    sshbuf_reset(sig_pkt.data);

    /* Now add the subkey for the new curve25519 key */
    if (retval == 0) {
        gpg_packet public_subkey_pkt;
        generate_gpg_curve25519_subkey_packet(pub_subkey, crypto_box_PUBLICKEYBYTES, &public_subkey_pkt);
        compute_gpg_key_fingerprint(&public_subkey_pkt, subkey_fp);
        generate_gpg_pk_uid_signature_packet(&public_subkey_pkt, NULL, ssh_key, GPG_SIGCLASS_SUBKEY_BIND,
                key_id, &sig_pkt);

        retval = put_gpg_packet(pub_file, &public_subkey_pkt);

        if (retval == 0) {
            retval = put_gpg_packet(pub_file, &sig_pkt);
            if (retval == 0) {
                retval = put_gpg_packet(pub_file, &trust_pkt);
            }
        }
        sshbuf_free(public_subkey_pkt.data);
        sshbuf_free(sig_pkt.data);
        sshbuf_free(trust_pkt.data);
    }
    fclose(pub_file);

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
 *  @param ssh_key RSA key, both public and secret parts
 *  @param q Cv25519 public key
 *  @param q_len num bytes in q
 *  @param d Cv25519 secret key
 *  @param d_len num bytes in d
 *  @return int 0 if successful, negative number if error
 */
static int
write_secret_key_files(const Key * ssh_key, const u_char * q, int q_len, const u_char * d, int d_len,
                       const char * passphrase)
{
    int retval = -1;

    FILE * rsa_key_file = open_rsa_seckey_file("w", ssh_key);
    if (rsa_key_file != NULL) {
        fchmod(fileno(rsa_key_file), S_IRUSR | S_IWUSR);    //  600 perms.

        struct sshbuf * rsa_seckey = generate_gpg_rsa_seckey(ssh_key, passphrase);
        if (rsa_seckey != NULL) {
            if (fwrite(sshbuf_ptr(rsa_seckey), 1, sshbuf_len(rsa_seckey), rsa_key_file) ==
                        sshbuf_len(rsa_seckey)) {
                FILE * c_key_file = open_curve25519_seckey_file("w", q, q_len);
                if (c_key_file != NULL) {
                    fchmod(fileno(c_key_file), S_IRUSR | S_IWUSR);  //  600 perms.
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

    return retval;
}

/**
 *  Create a directory under the ~/.ssh/ironcore directory
 *
 *  If the subdirectory name is not provided (NULL), create ~/.ssh/ironcore.
 *
 *  @param subdir Name of the subdirectory to create
 *  @return int 0 if successful, negative number if error
 */
static int
make_ironcore_subdir(const char * subdir)
{
    int retval = -1;
    char dir_name[PATH_MAX];

    if (subdir) snprintf(dir_name, PATH_MAX, "%s%s/", iron_user_ironcore_dir(), subdir);
    else strlcpy(dir_name, iron_user_ironcore_dir(), PATH_MAX);

    if (mkdir(dir_name, 0700) == 0 || errno == EEXIST) {
        retval = 0;
    } else {
        error("Could not create directory \"%s\" - %s.", dir_name, strerror(errno));
    }

    return retval;
}

/**
 *  Create the set of directories under ~/.ssh for ironcore data.
 *
 *  Create the ~/.ssh/ironcore directory and the required subdirectories under it.
 */
static int
create_iron_dirs(void)
{
    if (make_ironcore_subdir(NULL) == 0 && make_ironcore_subdir(IRON_PUBKEY_SUBDIR) == 0 &&
            make_ironcore_subdir(GPG_SECKEY_SUBDIR) == 0) return 0;
    else return -1;
}

/**
 *  Create new GPG key files for use by ironsftp.
 *
 *  Randomly generate a curve25519 key pair, then create a new GPG-compatible public key file containing the
 *  SSH key (currently only RSA keys supported) as the "signing key" and the curve25519 key as a subkey. This
 *  file is written to ~<login>/.ssh/ironcore/pubkey.gpg. Also create ~<login>/.ssh/ironcore/trustdb.gpg, a
 *  file that records trust in public keys.
 *
 *  Once the public key file is created, create two of the GPG-compatible new-format secret key files, one for
 *  the RSA key and one for the curve25519 subkey, under ~<login>/.ssh/ironcore/private-keys-v1.d.
 *
 *  In order to protect the secret parameters in the secret key files, we need a passphrase, and we don't have
 *  access to the passphrase from the SSH key file, so we generate a new passphase using the secret key params
 *  from the SSH key.
 *
 *  @param login Login of the user - most likely the user running the executable
 *  @return int 0 if successful, negative number if error
 */
int
iron_generate_keys(void)
{
    int retval = -1;
    printf("\nYou do not appear to have IronCore keys in your .ssh directory\n"
           "(%s), so they will be generated for you.\n\n"
           "To do this, you need to have an RSA key stored in ~/.ssh/%s.\n"
           "You may be prompted to enter your passphrase to continue, to prove that you\n"
           "have access to your private RSA key.\n\n"
           "Your %s and %s.pub files will be copied to ~/.ssh/%s.\n"
           "A new key file, ~/.ssh/%s%s, will be created and\n"
           "populated with signing and encryption keys that will transparently secure\n"
           "any file that you upload ('put') or download ('get').\n\n"
           "NOTE: the new key files are compatible with GPG v. 2.1.14 and newer.\n",
           iron_user_ssh_dir(), SSH_KEY_FNAME, SSH_KEY_FNAME, SSH_KEY_FNAME, IRONCORE_SUBDIR, IRONCORE_SUBDIR,
           GPG_PUBLIC_KEY_FNAME);

    u_char pub_key[crypto_box_PUBLICKEYBYTES];
    u_char sec_key[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(pub_key, sec_key);
    clamp_and_reverse_seckey(sec_key);

    Key * ssh_key;
    char * comment;

    if (create_iron_dirs() == 0 && copy_ssh_key_files() == 0 && retrieve_ssh_key(&ssh_key, &comment) == 0) {
        char file_name[PATH_MAX];
        snprintf(file_name, PATH_MAX, "%s%s", iron_user_ironcore_dir(), GPG_PUBLIC_KEY_FNAME);
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
                uid = iron_user_login();
            }

            if (write_public_key_file(ssh_key, pub_key, uid, key_fp, subkey_fp) == 0) {
                char passphrase[512];
                if ((generate_gpg_passphrase_from_rsa(ssh_key, passphrase) == 0) &&
                    (write_secret_key_files(ssh_key, pub_key, sizeof(pub_key), sec_key,
                            sizeof(sec_key), passphrase) == 0)) {
                    printf("\nGenerated new GPG secret keys - they are protected with the passphrase\n"
                           "    %s\n\n"
                           "You will need this passphrase if you want to decrypt any '.iron' files\n"
                           "directly with GPG. No need to store it, though - it is generated using\n"
                           "your SSH RSA key, so you can use the iron-passphrase utility to generate\n"
                           "it at any time. You just need to enter the passphrase for your RSA key.\n\n",
                           passphrase);

                    if (write_gpg_trustdb_file(key_fp, sizeof(key_fp), uid) == 0 &&
                        write_pubkey_file(ssh_key, key_fp, pub_key, subkey_fp) == 0) {
                        retval = 0;
                    }
                }
            }
            fclose(pub_file);
        } else {
            error("Unable to open \"%s\" to write public key.", file_name);
        }
    }

    return retval;
}

/**
 *  Confirm that public and private key files are in place for the current user.
 *
 *  Check to see if the public/private key files containing the specified login's rsa & curve25519 keys
 *  exist and are accessible. If not, and if we have access to the login's .ssh directory, try to create
 *  new files.
 *
 *  @return int 1 if keys in place, 0 if not, -1 if error
 */
int
iron_check_keys(void)
{
    if (iron_initialize() != 0) return -1;

    int retval = -1;
    char file_name[PATH_MAX];
    snprintf(file_name, PATH_MAX, "%s%s%s", iron_user_ssh_dir(), IRONCORE_SUBDIR, GPG_PUBLIC_KEY_FNAME);

    if (access(file_name, F_OK) == 0) {
        snprintf(file_name, PATH_MAX, "%s%s", iron_user_ironcore_dir(), GPG_SECKEY_SUBDIR);
        //  If the directory is there, assume that the key files are in place.
        if (access(file_name, F_OK) == 0) retval = 1;
    }

    if (retval < 0) {
        if (errno == ENOENT) retval = 0;
        else if (errno == EACCES) error("No access to \"%s\".", file_name);
        else error("Error checking \"%s\" - %s", file_name, strerror(errno));
    }

    return retval;
}

/**
 *  Retrieve secret part of RSA signing key pair.
 *
 *  Retrieve the secret RSA signing key for the login that is running the process. Given the public
 *  keys for that user, makes sure the secret key is not already fetched. (The rsa_key parm is a pointer
 *  to the key stored in the recipient list, which is cached during process run). If the secret key is not,
 *  available, uses the public encryption key to compute the keygrip, open the secret key file, then
 *  retrieve the secret key from that file. This requires the passphrase, which requires the RSA public key as well
 *  (to generate the passphrase).
 *
 *  @param rsa_key RSA key. If successful, private part of RSA key is populated
 *  @return int 0 if successful, negative number if error
 */
int
get_gpg_secret_signing_key(Key * rsa_key)
{
    if (rsa_key->rsa->d != NULL) return 0;      //  Already fetched

    int retval = -1;
    FILE * infile = open_rsa_seckey_file("r", rsa_key);
    if (infile != NULL) {
        u_char buf[4096];       //  Just picked a big number to hold entire file

        int num_read = fread(buf, 1, sizeof(buf), infile);
        retval = extract_gpg_rsa_seckey(buf, num_read, rsa_key);
        fclose(infile);
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
int
get_gpg_secret_encryption_key(const gpg_public_key * pub_keys, u_char * sec_key)
{
    static u_char cached_sec_key[crypto_box_SECRETKEYBYTES];
    static size_t cached_sec_key_len = 0;

    if (cached_sec_key_len > 0) {
        memcpy(sec_key, cached_sec_key, cached_sec_key_len);
        return cached_sec_key_len;
    }
    
    int retval = -1;
    FILE * infile = open_curve25519_seckey_file("r", pub_keys->key, sizeof(pub_keys->key));
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

    return retval;
}

//================================================================================
//  Functions to maintain an index of key IDs and the user@host pubkeys that have
//  those key IDs.
//
//  Nothing fancy - just create files in ~/.ssh/ironcore/pubkeyidx named with
//  the key ID, containing a line for each pubkey file that contains a key with
//  that key ID. The line contains the type of key (e.g. iron-rsa), ": ", and
//  the name of the file (<user>@<host>)
//================================================================================

/**
 *  Open index file for the specified key ID.
 *
 *  Given a key ID, create or open the index file ~/.ssh/ironcore/pubkeyidx/<keyid>
 *  in the specified mode.
 *
 *  @param key_id ID of the key for which to open index file
 *  @param mode Mode string for fopen - either "a+", if indexing a file, or "r" if searching
 *  @return FILE * Pointer to opened file, or NULL if unable to open
 */
static FILE *
open_pubkey_idx_file(const u_char * key_id, const char * mode)
{
    char hex_id[2 * GPG_KEY_ID_LEN + 1];
    iron_hex2str(key_id, GPG_KEY_ID_LEN, hex_id);

    char fname[PATH_MAX];
    snprintf(fname, sizeof(fname), "%s%s%s", iron_user_ironcore_dir(), IRON_PUBKEYIDX_SUBDIR, hex_id);
    return fopen(fname, mode);
}

/**
 *  Create/update index file for key ID
 *
 *  Given a key ID, create or open the index file ~/.ssh/ironcore/pubkeyidx/keyid.
 *  Look through the file for an line like iron_<key_type>: <login>@<host>. If not found, append
 *  that line to the file.
 *
 *  @param key_id Key ID to index
 *  @param login User to associate with key ID
 *  @param key_type Either "rsa" or "cv25519", currently
 *  @return 0 if successful, negative number if error
 */
static int
index_public_key(const u_char * key_id, const char * login, const u_char * key_type)
{
    int retval = -1;
    FILE * idx_file = open_pubkey_idx_file(key_id, "a+");
    if (idx_file != NULL) {
        char entry[MAX_IDX_LINE_LEN];
        snprintf(entry, sizeof(entry), "iron-%s: %s@%s", key_type, login, iron_host());
        rewind(idx_file);
        char line[MAX_IDX_LINE_LEN];
        while (fgets(line, sizeof(line), idx_file)) {
            if (strcmp(line, entry) == 0) {
                retval = 0;
                break;
            }
        }
        if (feof(idx_file)) {
            //  If we made it to the end of the file without finding the target entry,
            //  add it to the file.
            fputs(entry, idx_file);
            fputc('\n', idx_file);
            retval = 0;
        }
        fclose(idx_file);
    } else {
        char hex_id[2 * GPG_KEY_ID_LEN + 1];
        iron_hex2str(key_id, GPG_KEY_ID_LEN, hex_id);
        error("Error opening index file for key ID %s - %s.", hex_id, strerror(errno));
    }

    return retval;
}

/**
 *  Write index files for a set of public keys.
 *
 *  Given a login's RSA and CV25519 keys, write the index files that map the key IDs to the user's
 *  pubkey files.
 *
 *  @param keys Public key structure to index
 *  @return int 0 if successful, negative number if problem
 */
int
iron_index_public_keys(gpg_public_key * keys)
{
    int retval = 0;

    if (*keys->signer_fp) retval = index_public_key(GPG_KEY_ID_FROM_FP(keys->signer_fp), keys->login, "rsa");
    if (retval == 0 && *keys->fp) retval = index_public_key(GPG_KEY_ID_FROM_FP(keys->fp), keys->login, "cv25519");

    return retval;
}

/**
 *  Return the login for a specific key ID.
 *
 *  Searches the public key index. If the entry is found, look for a pubkey entry that matches the current host.
 *  If that is found, return the login the corresponding user.
 *
 *  @param key_id ID whose keys to fetch
 *  @returns char * Pointer to login for user, NULL if login couldn't be retrieved. Points to static array, so
 *                  copy before calling again if you need to keep it
 */
char *
iron_get_user_by_key_id(const char * key_id)
{
    char * lptr = NULL;
    static char login[IRON_MAX_LOGIN_LEN + 1];

    FILE * idx_file = open_pubkey_idx_file(key_id, "r");
    if (idx_file != NULL) {
        //  Search the file for a line that ends in "@<current host>\n"
        int retval = -1;
        char line[MAX_IDX_LINE_LEN];
        char target[MAX_IDX_LINE_LEN];
        snprintf(target, sizeof(target), "@%s\n", iron_host());
        char * host_ptr;
        while (fgets(line, MAX_IDX_LINE_LEN, idx_file)) {
            host_ptr = line + strlen(line) - strlen(target);
            if (strcmp(host_ptr, target) == 0) {
                retval = 0;
                break;
            }
        }
        if (retval == 0) {
            //  Found an entry in the file that matches the current host name. Compute offset of the
            //  contain our keys. Fetch the login, which should be the string before the @<host>,
            //  back to the preceding space.
            *host_ptr = '\0';
            char * login_ptr = strrchr(line, ' ');
            if (login_ptr != NULL) {
                login_ptr++;        //  Skip over ' '
                strlcpy(login, login_ptr, sizeof(login));
                lptr = login;
            }
        }
        fclose(idx_file);
    }

    return lptr;
}

/**
 *  Return the public keys for a specific key ID.
 *
 *  Searches the public key index. If the entry is found, look for a pubkey entry that matches the current host.
 *  If that is found, load the keys for the corresponding user.
 *
 *  @param key_id ID whose keys to fetch
 *  @returns gpg_public_key * Pointer to key values for user, NULL if keys couldn't be retrieved. Caller must free
 */
gpg_public_key *
iron_get_user_keys_by_key_id(const char * key_id)
{
    gpg_public_key * keys = NULL;
    char * login = iron_get_user_by_key_id(key_id);
    if (login != NULL) {
        keys = malloc(sizeof(gpg_public_key));

        strlcpy(keys->login, login, IRON_MAX_LOGIN_LEN);
        size_t key_len;
        bzero(&(keys->rsa_key), sizeof(keys->rsa_key));
        keys->rsa_key.type = KEY_RSA;
        keys->rsa_key.ecdsa_nid  = -1;
        if (read_pubkey_file(login, &(keys->rsa_key), keys->signer_fp, keys->key, &key_len,
                                keys->fp) < 0) {
            free(keys);
            keys = NULL;
        }
    }

    return keys;
}

/**
 *  Given a login, try to add user's pubkey info to key ID index
 *
 *  Assumes the pubkey file for login@host has already been written to ~/.ssh/ironcore/pubkeys.
 *  Tries to load the file and write the info to the key ID index for the keys from that file.
 *
 *  @param login User whose public keys to index
 *  @return 0 if successful, -1 if unable to index
 */
int
iron_index_user(const char * login)
{
    //  We don't add the current user to the index.
    if (strcmp(login, iron_user_login()) == 0) return 0;

    int retval = -1;

    gpg_public_key keys;
    strncpy(keys.login, login, IRON_MAX_LOGIN_LEN);
    keys.login[IRON_MAX_LOGIN_LEN] = 0;
    size_t key_len;
    bzero(&(keys.rsa_key), sizeof(keys.rsa_key));
    keys.rsa_key.type = KEY_RSA;
    keys.rsa_key.ecdsa_nid  = -1;
    if (get_gpg_public_keys(login, &(keys.rsa_key), keys.signer_fp, keys.key, &key_len,
                            keys.fp) == 0) {
        iron_index_public_keys(&keys);
        retval = 0;
    }

    return retval;
}
