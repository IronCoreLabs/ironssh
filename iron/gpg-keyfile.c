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
#define IRON_SSH_KEY_FNAME      "id_rsa.iron"
#define SSH_KEY_PUB_EXT         ".pub"
#define GPG_PUBLIC_KEY_FNAME    "pubring.gpg"
#define GPG_SECKEY_SUBDIR       "private-keys-v1.d"

#define GPG_MAX_UID_LEN         128     //  Max # bytes for a user ID / comment on a public SSH key
#define MAX_PASSPHRASE_RETRIES  3       //  Number of times user is prompted to enter passphrase to access SSH key


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
    iron_hex2str(keygrip, sizeof(keygrip), hexgrip);

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
    iron_hex2str(keygrip, sizeof(keygrip), hexgrip);

    char fname[512];
    FILE * infile = NULL;

    int len = snprintf(fname, sizeof(fname), "%s/%s.key", seckey_dir, hexgrip);

    if (len < 512) {
        infile = fopen(fname, mode);
    }
    return infile;
}

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
 *  Read login's ~/.pubkey file.
 *
 *  Retrieve the IronCore public key entries from the specified login's .pubkey file.
 *
 *  @param login User whose key info to retrieve
 *  @param rsa_key Place to write public portion of RSA key from .pubkey (at least GPG_MAX_KEY_SIZE bytes)
 *  @param rsa_key_len Place to write num bytes in rsa_key
 *  @param cv25519_key Place to write public portion of Curve25519 key (at least crypto_box_SECRETKEYBYTES bytes)
 *  @param cv25519_key_len Place to write num bytes in cv25519_key
 *  @param rsa_fp Place to write fingerprint of RSA key (at least GPG_KEY_FP_LEN bytes)
 *  @param cv25519_fp Place to write fingerprint of Curve25519 key (at least GPG_KEY_FP_LEN bytes)
 *  @param uid Place to write "user ID" string associated with the keys (at least GPG_MAX_UID_LEN bytes)
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
                        token = strsep(&lptr, " ");     // Skip the e value
                    }
                    token = strsep(&lptr, " ");
                    if (rsa_fp != NULL) {
                        int fp_len = iron_str2hex(token, rsa_fp, GPG_KEY_FP_LEN);
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
                        if (iron_str2hex(token, cv25519_fp, GPG_KEY_FP_LEN) != GPG_KEY_FP_LEN) {
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

/**
 *  Write a line to the user's .pubkey file containing specified RSA key info.
 *
 *  Write the key name, public key n, public key e, fingerprint, and UID in one line to the file.
 *  Writes the key name as "iron-rsa".
 *
 *  @param outfile File to which to write line
 *  @param key RSA key to write as two hex strings (n and e)
 *  @param fp Byte array containing key fingerprint. Converted to hax string
 *  @param uid String identifying user (typically "Name <emailaddr>")
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
    iron_hex2str(pval, plen, tmp);
    if (fprintf(outfile, "iron-rsa: %s ", tmp) > 0) {
        plen = BN_bn2bin(rsa_key->rsa->e, pval);
        iron_hex2str(pval, plen, tmp);
        fprintf(outfile, "%s ", tmp);
        iron_hex2str(fp, GPG_KEY_FP_LEN, tmp);
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
 *  @param uid String identifying user (typically "Name <emailaddr>")
 *  @return int 0 if successful, negative number if error
 */
static int
write_key_to_pubkey(FILE * outfile, const char * key_name, const u_char * pub_key, int len,
                    const u_char * fp, const char * uid)
{
    int retval = -1;

    u_char tmp[2 * GPG_MAX_KEY_SIZE + 1];
    iron_hex2str(pub_key, len, tmp);
    if (fprintf(outfile, "iron-%s: %s ", key_name, tmp) > 0) {
        iron_hex2str(fp, GPG_KEY_FP_LEN, tmp);
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
 *  @param uid String identifying user (typically "Name <emailaddr>")
 *  @param key_fp Byte array containing fingerprint for RSA key
 *  @param subkey_fp Byte array containing fingerprint for cv25519 key
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
int
iron_retrieve_ssh_private_key(const char * ssh_dir, const char * prompt, Key ** key)
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
 *  public key parameters were fetched along with private key parameters by iron_retrieve_ssh_private_key.
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
    int retval = iron_retrieve_ssh_private_key(ssh_dir, "Enter passphrase for SSH key file: ", key);

    //  If we succeeded in reading the private key, read the public key to get the comment field,
    //  which will typically be the user's identification (i.e. email address)
    if (retval == 0) {
        retval = retrieve_ssh_public_key(ssh_dir, comment);
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
int
get_gpg_public_keys(const char * login, Key * rsa_key, u_char * rsa_fp, u_char * key,
                    size_t * key_len, u_char * fp)
{
    int retval = read_pubkey_file(login, rsa_key, rsa_fp, key, key_len, fp, NULL);
    if (retval != 0) {
        //  Couldn't get data from the user's .pubkey file - fetch from pubring.gpg
        char key_file_name[PATH_MAX];
        FILE * key_file;

        const char * ssh_dir = iron_get_user_ssh_dir(login);
        snprintf(key_file_name, PATH_MAX, "%s%s", ssh_dir, GPG_PUBLIC_KEY_FNAME);
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
 *  Check whether the ssh directory contains a private key subdir.
 *
 *  Looks in the specified path for a private-keys-v1.d subdirectory.
 *
 *  @param ssh_dir Path to the user's .ssh directory (usually under ~<login>
 *  @return char * Path of private key subdir (at least PATH_MAX chars). Caller should free
 */
char *
iron_check_seckey_dir(const char * ssh_dir)
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
    gpg_packet public_key_pkt;
    gpg_packet user_id_pkt;
    gpg_packet sig_pkt;
    gpg_packet trust_pkt;

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
    char * seckey_dir = iron_check_seckey_dir(ssh_dir);

    if (seckey_dir) {
        FILE * rsa_key_file = open_rsa_seckey_file(seckey_dir, "w", ssh_key);

        if (rsa_key_file != NULL) {
            fchmod(fileno(rsa_key_file), S_IRUSR | S_IWUSR);    //  600 perms.

            struct sshbuf * rsa_seckey = generate_gpg_rsa_seckey(ssh_key, passphrase);
            if (rsa_seckey != NULL) {
                if (fwrite(sshbuf_ptr(rsa_seckey), 1, sshbuf_len(rsa_seckey), rsa_key_file) ==
                            sshbuf_len(rsa_seckey)) {
                    FILE * c_key_file = open_curve25519_seckey_file(seckey_dir, "w", q, q_len);
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
        free(seckey_dir);
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

                        if (write_gpg_trustdb_file(ssh_dir, key_fp, sizeof(key_fp), uid) == 0 &&
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
    if (iron_initialize() != 0) return -1;

    int retval = -1;
    const char * ssh_dir = iron_get_user_ssh_dir(iron_user_login());
    if (ssh_dir != NULL && *ssh_dir) {
        char file_name[PATH_MAX];
        snprintf(file_name, PATH_MAX, "%s%s", ssh_dir, GPG_PUBLIC_KEY_FNAME);

        if (access(file_name, F_OK) == 0) {
            char * seckey_dir = iron_check_seckey_dir(ssh_dir);
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
                retval = generate_iron_keys(ssh_dir, iron_user_login());
            }
            else {
                error("Error checking \"%s\" - %s", file_name, strerror(errno));
            }
        }
    } else {
        error("Unable to find .ssh directory for user %s\n", iron_user_login());
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
	const char * ssh_dir = iron_get_user_ssh_dir(iron_user_login());
	char * seckey_dir = iron_check_seckey_dir(ssh_dir);
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
    const char * ssh_dir = iron_get_user_ssh_dir(iron_user_login());
    char * seckey_dir = iron_check_seckey_dir(ssh_dir);
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

