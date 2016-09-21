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
#include "pathnames.h"
#include "authfile.h"
#include "log.h"
#include "misc.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "xmalloc.h"

#include "iron-common.h"
#include "iron-gpg.h"
#include "iron/gpg-internal.h"
#include "iron/gpg-key.h"
#include "iron/gpg-keyfile.h"
#include "iron/gpg-packet.h"
#include "iron/gpg-trustdb.h"
#include "iron/util.h"


#define IRON_SSH_KEY_FNAME      "id_iron"
#define SSH_KEY_PUB_EXT         ".pub"
#define GPG_PUBLIC_KEY_FNAME    "pubring.gpg"
#define GPG_SECKEY_SUBDIR       "private-keys-v1.d/"
#define IRON_PUBKEY_LOCAL_FNAME "ironpubkey"    //  Name of file created in ~/.ssh/ironcore
#define IRON_PUBKEY_SUBDIR      "pubkeys/"      //  Name of ~/.ssh/ironcore subdir that holds other users' public keys
#define IRON_PUBKEYIDX_SUBDIR   "pubkeyidx/"    //  Name of ~/.ssh/ironcore subdir that holds index of pubkeys by
                                                //      key ID

#define GPG_MAX_UID_LEN         128     //  Max # bytes for a user ID / comment on a public SSH key
#define MAX_PASSPHRASE_RETRIES  3       //  Number of times user is prompted to enter passphrase to access SSH key
#define MAX_IDX_LINE_LEN        256     //  Room for "iron-cv25519: <user>@<host>


/*  Names of files that by default contain SSH keys, in the order in which SSH searches for a match. Each file name
 *  is preceded by ".ssh/".
 */
static char * ssh_identity_fname[] = {
    _PATH_SSH_CLIENT_ID_RSA,
    _PATH_SSH_CLIENT_ID_ED25519,
    _PATH_SSH_CLIENT_ID_DSA,
    _PATH_SSH_CLIENT_ID_ECDSA
};
#define NUM_SSH_IDENTITY_FNAMES     ((int) (sizeof(ssh_identity_fname) / sizeof(char *)))

/**
 *  Open a file containing the GPG public keys
 *
 *  File should be in ~/.ssh/ironcore/pubring.gpg.
 *
 *  @return FILE * pointer to file opened for read, or NULL if error
 */
static FILE *
open_pubkey_file(void)
{
    char key_file_name[PATH_MAX];

    snprintf(key_file_name, PATH_MAX, "%s%s", iron_user_ironcore_dir(), GPG_PUBLIC_KEY_FNAME);
    return fopen(key_file_name, "r");
}

/**
 *  Open a file containing a secret key
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
 *  Open the file containing the ed25519 secret key
 *
 *  Compute keygrip of ed25519 public key, convert to hex string, and open the secret key file.
 *
 *  @param mode String specifying mode for fopen()
 *  @param pub_key Ed25519 public key
 *  @return FILE * File containing Ed25519 secret key, opened for in specified mode
 */
static FILE *
open_ed25519_seckey_file(const char * mode, const u_char * pub_key)
{
    u_char keygrip[SHA_DIGEST_LENGTH];
    char hexgrip [2 * SHA_DIGEST_LENGTH + 1];

    generate_gpg_ed25519_keygrip(pub_key, keygrip);
    iron_hex2str(keygrip, sizeof(keygrip), hexgrip);

    return open_seckey_file(mode, hexgrip);
}

/**
 *  Open the file containing the cv25519 secret key
 *
 *  Compute keygrip of cv25519 public key, convert to hex string, and open the secret key file.
 *
 *  @param mode String specifying mode for fopen()
 *  @param pub_key Cv25519 public key
 *  @return FILE * File containing cv25519 secret key, opened for in specified mode
 */
static FILE *
open_curve25519_seckey_file(const char * mode, const u_char * pub_key)
{
    u_char keygrip[SHA_DIGEST_LENGTH];
    char hexgrip [2 * SHA_DIGEST_LENGTH + 1];

    generate_gpg_curve25519_keygrip(pub_key, keygrip);
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
copy_ssh_key_file(const char * fname, const char * ext)
{
    int retval = -1;
    char cp_cmd[2 * PATH_MAX + 4];   //  Room for "cp " and two file names, space-separated, with NULL term.

    char ssh_key_file[PATH_MAX];
    snprintf(ssh_key_file, PATH_MAX, "%s%s", fname, ext);

    if (access(ssh_key_file, F_OK) == 0) {
        char iron_key_file[PATH_MAX];
        snprintf(iron_key_file, PATH_MAX, "%s%s%s", iron_user_ironcore_dir(), IRON_SSH_KEY_FNAME, ext);

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
copy_ssh_key_files(const char * fname)
{
    int retval = -1;

    if (copy_ssh_key_file(fname, "") == 0) {
        if (copy_ssh_key_file(fname, SSH_KEY_PUB_EXT) == 0) {
            retval = 0;
        }
    }

    return retval;
}

/**
 *  Attempt to locate default SSH key file
 *
 *  Go through ssh list of default identity file names and find the highest-priority match,
 *  assuming they are in the ~/.ssh directory.
 *
 *  @param file_path place to write path to file (PATH_MAX chars)
 *  @return 0 if successful, negative number if no file found or error
 */
static int
get_default_ssh_key_path(char * file_path)
{
    int retval = -1;
    int i;

    for (i = 0; i < NUM_SSH_IDENTITY_FNAMES; i++) {
        snprintf(file_path, PATH_MAX, "%s%s", iron_user_dir(), ssh_identity_fname[i]);
        if (access(file_path, F_OK) == 0) {
            break;
        }
    }

    if (i < NUM_SSH_IDENTITY_FNAMES) retval = 0;
    else *file_path = '\0';

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
 *  Helper function to generate the path. This will be ~/.ssh/pubkeys/<login>@<host>.
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
 *  Process line from public key file
 *
 *  Try to recover the key and the fingerprint of an ECC key (Ed25519, Cv25519) from a line in a .ironpubkey
 *  file. The line should look like
 *    iron-<keytype>: <pubkey value, hex encoded> <fingerprint, hex encoded>
 *
 *  @param line Line of input file to parse
 *  @param key Place to write the recovered key value (decoded from hex, key_len bytes)
 *  @param key_len Num bytes in key
 *  @param fp Place to write recovered fingerprint (decoded from hex, GPG_MAX_KEY_LEN bytes)
 *  @return 0 if successful, negative number if error
 */
static int
read_pubkey_line(char * line, u_char * key, int key_len, u_char * fp)
{
    int retval = 0;
    char * lptr = line;
    char * token;

    token = strsep(&lptr, " ");     //  Skip initial key type (i.e. "iron-cv25519: ")
    token = strsep(&lptr, " ");     //  Find end of the public key string
    retval = iron_str2hex(token, key, key_len);

    if (retval > 0) {
        token = strsep(&lptr, " \n");
        if (iron_str2hex(token, fp, GPG_KEY_FP_LEN) != GPG_KEY_FP_LEN) retval = -1;
        else retval = 0;
    }

    return retval;
}

/**
 *  Process line containing RSA key from public key file
 *
 *  Try to recover the key and the fingerprint of an RSA key from a line in a .ironpubkey file.
 *  The line should look like
 *    iron-rsa: <n value, hex encoded> <e value, hex encoded> <fingerprint, hex encoded>
 *
 *  @param line Line of input file to parse
 *  @param key Place to write the recovered RSA key value (public params only)
 *  @param fp Place to write recovered fingerprint (decoded from hex, GPG_MAX_KEY_LEN bytes)
 *  @return 0 if successful, negative number if error
 */
static int
read_pubkey_rsa_line(char * line, Key * key, u_char * fp)
{
    int retval = -1;
    char * lptr = line;
    char * token;

    u_char param[GPG_MAX_KEY_SIZE];

    token = strsep(&lptr, " ");     //  Skip initial key type (i.e. "iron-cv25519: ")
    token = strsep(&lptr, " ");     //  Find end of the public key string
    int len = iron_str2hex(token, param, sizeof(param));

    if (len > 0) {
        key->type = KEY_RSA;
        key->rsa = RSA_new();
        key->rsa->n = BN_new();
        BN_bin2bn(param, len, key->rsa->n);
        token = strsep(&lptr, " ");     // Next string should be the e value
        len = iron_str2hex(token, param, GPG_MAX_KEY_SIZE);
        if (len > 0) {
            key->rsa->e = BN_new();
            BN_bin2bn(param, len, key->rsa->e);

            token = strsep(&lptr, " \n");
            if (iron_str2hex(token, fp, GPG_KEY_FP_LEN) == GPG_KEY_FP_LEN) retval = 0;
        }
    }

    return retval;
}

/**
 *  Read .ironpubkey file for login and current host
 *
 *  Retrieve the IronCore public key entries from the specified login's .ironpubkey file associated with the
 *  current host (read from ~/.ssh/ironcore/pubkeys/<login>@<host>).
 *
 *  @param login User whose key info to retrieve
 *  @param sign_key Place to write public portion of signing key from .ironpubkey (crypto_sign_SECRETKEYBYTES)
 *  @param sign_fp Place to write fingerprint of signing key (at least GPG_KEY_FP_LEN bytes)
 *  @param enc_key Place to write public portion of encryption key (crypto_box_SECRETKEYBYTES)
 *  @param enc_fp Place to write fingerprint of encryption key (at least GPG_KEY_FP_LEN bytes)
 *  @param rsa_key Place to write public portion of RSA signing key (if it exists)
 *  @param rsa_fp Place to write fingerprint of rsa key (at least GPG_KEY_FP_LEN bytes)
 *  @return int 0 if successful, negative number if error
 */
static int
read_pubkey_file(gpg_public_key * pub_keys)
{
    int retval = -1;

    FILE * infile;
   
    if (strcmp(pub_keys->login, iron_user_login()) == 0) infile = fopen(iron_user_pubkey_file(), "r");
    else infile = fopen(iron_pubkey_file(pub_keys->login), "r");

    if (infile != NULL) {
        retval = 0;
        char line[3000];
        while (retval == 0 && fgets(line, sizeof(line), infile)) {
            if (strncmp(line, "iron-ed25519:", 13) == 0) {
                retval = read_pubkey_line(line, pub_keys->sign_key, crypto_sign_PUBLICKEYBYTES, pub_keys->sign_fp);
            } else if (strncmp(line, "iron-cv25519:", 13) == 0) {
                retval = read_pubkey_line(line, pub_keys->enc_key, crypto_box_PUBLICKEYBYTES, pub_keys->enc_fp);
            } else if (strncmp(line, "iron-rsa:", 9) == 0) {
                retval = read_pubkey_rsa_line(line, &pub_keys->rsa_key, pub_keys->rsa_fp);
            }
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
 *  @param key_name Name used to identify key (e.g. "ed25519", "cv25519"). Will be prefixed by "iron-"
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
 *  Creates ~/.ssh/ironcore/ironpubkey, then write lines for the ed25519 key and the cv25519 key.
 *  If file already exists, it is overwritten.
 *
 *  @param pub_sign_key Public ed25519 key (crypto_sign_PUBLICKEYBYTES)
 *  @param sign_key_fp Byte array containing fingerprint for ed25519 key
 *  @param pub_enc_key Public cv25519 key (crypto_box_PUBLICKEYBYTES)
 *  @param enc_key_fp Byte array containing fingerprint for cv25519 key
 *  @return int 0 if successful, negative number if error
 */
static int
write_pubkey_file(const u_char * pub_sign_key, const u_char * sign_key_fp, const u_char * pub_enc_key,
                  const u_char * enc_key_fp)
{
    int retval = -1;

    FILE * outfile = fopen(iron_user_pubkey_file(), "w");
    if (outfile != NULL) {
        if (write_key_to_pubkey(outfile, "ed25519", pub_sign_key, crypto_sign_PUBLICKEYBYTES, sign_key_fp) == 0) {
            if (write_key_to_pubkey(outfile, "cv25519", pub_enc_key, crypto_box_PUBLICKEYBYTES, enc_key_fp) == 0) {
                fchmod(fileno(outfile), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
                fclose(outfile);
                retval = 0;
            }
        }
    }

    return retval;
}

static int
update_pubkey_file(u_char * pub_sign_key, u_char * sign_key_fp)
{
    int retval = -1;

    FILE * outfile = fopen(iron_user_pubkey_file(), "a");
    if (outfile != NULL) {
        retval = write_key_to_pubkey(outfile, "ed25519", pub_sign_key, crypto_sign_PUBLICKEYBYTES, sign_key_fp);
        fclose(outfile);
    }

    return retval;
}

/**
 *  Retrieve public part of signing and encryption key pairs for specified login.
 *
 *  If the login is not the current user, attempt to read the public parts of the signing (ed25519) key and
 *  encryption (cv25519) keys from the specified login's ~/.ironpubkey file.
 *  For the current login, read the public key and encryption subkey for the login from the 
 *  ~<login>/.ssh/ironcore/pubkey.gpg file.
 *
 *  @param login Name of the user for whom to find the key
 *  @param sign_key Place to put public portion of ed25519 key (at least crypto_sign_PUBLICKEYBYTES)
 *  @param sign_fp Place to put fingerprint of ed25519 key (at least GPG_KEY_FP_LEN bytes)
 *  @param enc_key Place to put public portion of cv25519 key (at least crypto_box_PUBLICKEYBYTES)
 *  @param enc_fp Place to put fingerprint of cv25519 key (at least GPG_KEY_FP_LEN bytes)
 *  @return int 0 if successful, negative number if error
 */
int
get_gpg_public_keys(const char * login, gpg_public_key * pub_keys)
{
    int retval = -1;

    bzero(pub_keys, sizeof(gpg_public_key));
    strlcpy(pub_keys->login, login, sizeof(pub_keys->login));
    retval = read_pubkey_file(pub_keys);
    if (strcmp(login, iron_user_login()) == 0) {
        //  Just to make sure, we fetch current login's keys from pubring.gpg instead of just using
        //  .ironpubkey. However, we read the ironpubkey file first, because if the user has an RSA
        //  signing key, it is only in the ironpubkey, and not in pubring.gpg.
        FILE * key_file = open_pubkey_file();
        if (key_file != NULL) {
            retval = 0;

            gpg_packet * pubkey_pkt = get_gpg_pub_key_packet(key_file);
            if (pubkey_pkt != NULL) {
                compute_gpg_key_fingerprint(pubkey_pkt, pub_keys->sign_fp);
                if (extract_gpg_ed25519_pubkey(pubkey_pkt->data, pub_keys->sign_key) != crypto_sign_PUBLICKEYBYTES) {
                    error("Invalid length for ed25519 public key.");
                    retval = -1;
                }
                sshbuf_free(pubkey_pkt->data);
                free(pubkey_pkt);
            } else {
                error("Unable to retrieve public signing key - could not recover data.");
                retval = -1;
            }

            if (retval == 0) {
                gpg_packet * subkey_pkt = get_gpg_curve25519_subkey_packet(key_file);
                if (subkey_pkt != NULL) {
                    compute_gpg_key_fingerprint(subkey_pkt, pub_keys->enc_fp);
                    if (extract_gpg_curve25519_pubkey(subkey_pkt->data, pub_keys->enc_key) !=
                            crypto_box_PUBLICKEYBYTES) {
                        error("Invalid length for curve25519 public key.");
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

static int
write_public_key_packets(FILE ** pub_file, const u_char * pub_sign_key, const u_char * sec_sign_key,
                         const char * uid, u_char * sign_key_fp)
{
    int retval = -1;
    gpg_packet public_key_pkt;
    gpg_packet user_id_pkt;
    gpg_packet sig_pkt;
    gpg_packet trust_pkt;

    char file_name[PATH_MAX];
    snprintf(file_name, PATH_MAX, "%s%s", iron_user_ironcore_dir(), GPG_PUBLIC_KEY_FNAME);
    *pub_file = fopen(file_name, "w");
    if (*pub_file == NULL) {
        error("Could not open %s to write public key data - %s.", file_name, strerror(errno));
        return -1;
    }
    fchmod(fileno(*pub_file), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    generate_gpg_ed25519_pubkey_packet(pub_sign_key, &public_key_pkt);
    compute_gpg_key_fingerprint(&public_key_pkt, sign_key_fp);
    u_char * sign_key_id = GPG_KEY_ID_FROM_FP(sign_key_fp);

    generate_gpg_user_id_packet(uid, &user_id_pkt);
    generate_gpg_pk_uid_signature_packet(&public_key_pkt, &user_id_pkt, sec_sign_key, GPG_SIGCLASS_POSITIVE_CERT,
                                         sign_key_id, &sig_pkt);
    generate_gpg_trust_packet(&trust_pkt);

    retval = put_gpg_packet(*pub_file, &public_key_pkt);

    if (retval == 0) {
        retval = put_gpg_packet(*pub_file, &user_id_pkt);
        if (retval == 0) {
            retval = put_gpg_packet(*pub_file, &sig_pkt);
            if (retval == 0) {
                retval = put_gpg_packet(*pub_file, &trust_pkt);
            }
        }
    }
    sshbuf_free(public_key_pkt.data);
    sshbuf_free(user_id_pkt.data);
    sshbuf_reset(sig_pkt.data);
    sshbuf_reset(trust_pkt.data);

    return retval;
}

static int
write_public_subkey_packets(FILE * pub_file, const u_char * sec_sign_key, const u_char * sign_key_id,
                            const gpg_packet * subkey_pkt)
{
    int retval = -1;
    gpg_packet sig_pkt;
    gpg_packet trust_pkt;

    generate_gpg_pk_uid_signature_packet(subkey_pkt, NULL, sec_sign_key, GPG_SIGCLASS_SUBKEY_BIND,
                                         sign_key_id, &sig_pkt);
    generate_gpg_trust_packet(&trust_pkt);

    retval = put_gpg_packet(pub_file, subkey_pkt);

    if (retval == 0) {
        retval = put_gpg_packet(pub_file, &sig_pkt);
        if (retval == 0) {
            retval = put_gpg_packet(pub_file, &trust_pkt);
        }
    }
    sshbuf_free(sig_pkt.data);
    sshbuf_free(trust_pkt.data);

    return retval;
}

/**
 *  Write GPG pubring.gpg file.
 *
 *  Assemble the packets for the user's public ed25519 key, UID, signature, public cv25519 subkey, UID, and
 *  signature into a pubring.gpg file in user's ~/ironcore/.ssh directory.
 *
 *  @param pub_sign_key public part of user's Ed25519 key pair
 *  @param sec_sign_key secret part of user's Ed25519 key pair
 *  @param pub_enc_key public part of user's cv25519 key pair
 *  @param uid String identifying user (name <emailaddr>, typically)
 *  @param sign_key_fp Place to write fingerprint of the Ed25519 key. (At least GPG_KEY_FP_LEN bytes)
 *  @param enc_key_fp Place to write fingerprint of the cv25519 key. (At least GPG_KEY_FP_LEN bytes)
 *  @return int 0 if successful, negative number if error
 */
static int
write_public_key_file(const u_char * pub_sign_key, const u_char * sec_sign_key, const u_char * pub_enc_key,
                      const char * uid, u_char * sign_key_fp, u_char * enc_key_fp)
{
    int retval = -1;
    FILE * pub_file = NULL;

    retval = write_public_key_packets(&pub_file, pub_sign_key, sec_sign_key, uid, sign_key_fp);

    /*  Now add the subkey for the new curve25519 key. */
    if (retval == 0) {
        u_char * sign_key_id = GPG_KEY_ID_FROM_FP(sign_key_fp);
        gpg_packet public_subkey_pkt;

        generate_gpg_curve25519_subkey_packet(pub_enc_key, &public_subkey_pkt);
        compute_gpg_key_fingerprint(&public_subkey_pkt, enc_key_fp);

        retval = write_public_subkey_packets(pub_file, sec_sign_key, sign_key_id, &public_subkey_pkt);

        sshbuf_free(public_subkey_pkt.data);
    }
    if (pub_file != NULL) fclose(pub_file);

    return retval;
}

static int
rewrite_public_key_file(const u_char * pub_sign_key, const u_char * sec_sign_key, const gpg_packet * subkey_pkt,
                        const char * uid, u_char * sign_key_fp)
{
    int retval = -1;
    FILE * pub_file = NULL;

    retval = write_public_key_packets(&pub_file, pub_sign_key, sec_sign_key, uid, sign_key_fp);

    /*  Now write the supplied subkey for the curve25519 key and add new signature packet for the subkey. */
    if (retval == 0) {
        u_char * sign_key_id = GPG_KEY_ID_FROM_FP(sign_key_fp);
        retval = write_public_subkey_packets(pub_file, sec_sign_key, sign_key_id, subkey_pkt);
    }
    if (pub_file != NULL) fclose(pub_file);

    return retval;
}

/**
 *  Write the files containing ed25519 and cv25519 secret keys
 *
 *  Generates the contents of each of the files and writes it to the private key subdirectory of the user's
 *  .ssh directory. Files are named with the keygrip of the key. The secret key parameter portions of the files
 *  are encrypted, using the supplied passphrase to generate the key. If the secret key files already exist,
 *  they are overwritten.
 *
 *  @param pub_sign_key Ed25519 public key (crypto_sign_PUBLICKEYBYTES)
 *  @param sec_sign_key Ed25519 secret key (crypto_sign_SECRETKEYBYTES)
 *  @param pub_enc_key  Cv25519 public key (crypto_box_PUBLICKEYBYTES)
 *  @param sec_enc_key  Cv25519 secret key (crypto_box_SECRETKEYBYTES)
 *  @param passphrase Generate passphrase used to secure secret keys
 *  @return int 0 if successful, negative number if error
 */
static int
write_secret_key_files(const u_char * pub_sign_key, const u_char * sec_sign_key, const u_char * pub_enc_key,
                       u_char * sec_enc_key, const char * passphrase)
{
    int retval = -1;

    if (pub_sign_key != NULL) {
        FILE * sign_key_file = open_ed25519_seckey_file("w", pub_sign_key);
        if (sign_key_file != NULL) {
            fchmod(fileno(sign_key_file), S_IRUSR | S_IWUSR);    //  600 perms.

            struct sshbuf * e_seckey = generate_gpg_ed25519_seckey(pub_sign_key, sec_sign_key, passphrase);
            if (e_seckey != NULL) {
                if (fwrite(sshbuf_ptr(e_seckey), 1, sshbuf_len(e_seckey), sign_key_file) == sshbuf_len(e_seckey)) {
                    retval = 0;
                } else {
                    error("Unable to write complete ed25519 secret key file.");
                }
                sshbuf_free(e_seckey);
            }
            fclose(sign_key_file);
        }
    } else retval = 0;

    if (pub_enc_key != NULL && retval == 0) {
        retval = -1;
        FILE * enc_key_file = open_curve25519_seckey_file("w", pub_enc_key);
        if (enc_key_file != NULL) {
            fchmod(fileno(enc_key_file), S_IRUSR | S_IWUSR);    //  600 perms.

            struct sshbuf * c_seckey = generate_gpg_curve25519_seckey(pub_enc_key, sec_enc_key, passphrase);
            if (c_seckey != NULL) {
                if (fwrite(sshbuf_ptr(c_seckey), 1, sshbuf_len(c_seckey), enc_key_file) == sshbuf_len(c_seckey)) {
                    retval = 0;
                } else {
                    error("Unable to write complete cv25519 secret key file.");
                }
                sshbuf_free(c_seckey);
            }
            fclose(enc_key_file);
        }
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
            make_ironcore_subdir(IRON_PUBKEYIDX_SUBDIR) == 0 && 
            make_ironcore_subdir(GPG_SECKEY_SUBDIR) == 0) {
        return 0;
    } else return -1;
}

/**
 *  Generate User ID (UID) string
 *
 *  Try to retrieve SSH public key's comment from ~/.ssh/ironcore/id_iron.pub. If that doesn't work,
 *  just set the UID to the user name.
 *
 *  @returns const char * UID string. Points to static memory - copy before calling again
 */
static const char *
get_uid(void)
{
    static char uid[128];

    char ssh_key_fname[PATH_MAX];
    snprintf(ssh_key_fname, PATH_MAX, "%s%s%s", iron_user_ironcore_dir(), IRON_SSH_KEY_FNAME, SSH_KEY_PUB_EXT);

    Key * tmp_key;
    char * comment;
    if (sshkey_load_public(ssh_key_fname, &tmp_key, &comment) == 0 && comment != NULL && *comment != '\0') {
        strlcpy(uid, comment, sizeof(uid));
        sshkey_free(tmp_key);
        free(comment);
    } else {
        char hostname[128];
        gethostname(hostname, sizeof(hostname));
        snprintf(uid, sizeof(uid), "%s@%s", iron_user_login(), hostname);
    }

    return uid;
}

/**
 *  Retrieve the public key parameters from ~/.ssh/ironcore/id_iron.pub
 *
 *  @param pub_key Place to write recovered key
 *  @return 0 if successful, negative number if error
 */
int
get_ssh_public_key(Key ** pub_key)
{
    char  pub_key_fname[PATH_MAX];
    snprintf(pub_key_fname, PATH_MAX, "%s%s%s", iron_user_ironcore_dir(), IRON_SSH_KEY_FNAME, SSH_KEY_PUB_EXT);
    if (sshkey_load_public(pub_key_fname, pub_key, NULL) != 0) {
        error("Unable to retrieve public keys from %s.", pub_key_fname);
        return -1;
    } else return 0;
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
 *  Try to fetch the private key from the id_iron file. Includes retries if user enters incorrect passphrase.
 *
 *  @param prompt String to display to user before reading passphrase ("" to suppress prompt and use no passphrase)
 *  @param key Place to write SSH key read from file.  Caller should sshkey_free
 *  @returns int 0 if successful, negative number if error
 */
int
get_ssh_private_key(Key ** key)
{
    int retval = -1;

    char ssh_key_file[PATH_MAX];
    snprintf(ssh_key_file, PATH_MAX, "%s%s", iron_user_ironcore_dir(), IRON_SSH_KEY_FNAME);

    //  Attempt to load the key with no passphrase, just in case
    retval = sshkey_load_private(ssh_key_file, "", key, NULL);
    if (retval == SSH_ERR_KEY_WRONG_PASSPHRASE) {
        int retry_ct = 0;
        retval = load_ssh_private_key(ssh_key_file, "Enter passphrase for SSH key: ", key);
        while (retval == SSH_ERR_KEY_WRONG_PASSPHRASE && retry_ct < MAX_PASSPHRASE_RETRIES) {
            retval = load_ssh_private_key(ssh_key_file, "Incorrect passphrase - try again: ", key);
            retry_ct++;
        }
    }

    return retval;
}

/**
 *  Create new GPG key files for use by ironsftp.
 *
 *  Randomly generate an Ed25519 key pair that will be used for signing and a curve25519 key pair that will be
 *  used for encryption, then create a new GPG-compatible public key file containing the signing key as the
 *  main key nad the encryption key as a subkey. This file is written to ~<login>/.ssh/ironcore/pubkey.gpg.
 *  Also create ~<login>/.ssh/ironcore/trustdb.gpg, a file that records trust in public keys.
 *
 *  Once the public key file is created, create two of the GPG-compatible new-format secret key files, one for
 *  the Ed25519 key and one for the curve25519 subkey, under ~<login>/.ssh/ironcore/private-keys-v1.d.
 *
 *  In order to protect the secret parameters in the secret key files, we need a passphrase, and we don't have
 *  access to the passphrase from the SSH key file, so we generate a new passphase by using the SSH key to sign
 *  some known data and base64 encoding a portion of the signature as the passphrase.
 *
 *  @param identity_path name of SSH key file to use (can be NULL - will try to fill in default file name if so)
 *  @return int 0 if successful, negative number if error
 */
int
iron_generate_keys(const char * identity_path)
{
    int retval = -1;

    char pub_key_path[PATH_MAX];
    if (identity_path == NULL || *identity_path == '\0') {
        if (get_default_ssh_key_path(pub_key_path) != 0) {
            error("Unable to determine an SSH key to use to protect new iron keys.\n"
                  "Rerun with the -i option to specify an SSH identity to use.");
            return -1;
        }
    } else {
        strlcpy(pub_key_path, identity_path, sizeof(pub_key_path));
    }

    printf("\nYou do not have IronCore keys in your directory\n   %s\n"
           "so new signing and encryption keys will be generated for you. To protect\n"
           "your new keys, we will use your SSH identity\n    %s,\n"
           "after copying it to\n   %s%s.\n",
           iron_user_ssh_dir(), pub_key_path, iron_user_ironcore_dir(), IRON_SSH_KEY_FNAME);
    if (strcmp(pub_key_path + strlen(pub_key_path) - 3, "dsa") == 0) {
        printf("\nWARNING: due to the way that DSA and ECDSA compute signatures, if you use one\n"
               "of these identities to secure your IronCore keys, you will need to enter your\n"
               "passphrase once in each SFTP session where you upload or download any files,\n"
               "even if you have the identity in ssh-agent.\n\n");
    }
    printf("If you would prefer to use a different SSH identity, exit the program,\n"
           "remove the file and directory\n   ~/.%s  and  %s,\n"
           "then rerun with the -i option to specify your preferred identity file.\n",
           IRON_PUBKEY_LOCAL_FNAME, iron_user_ironcore_dir());

    u_char pub_sign_key[crypto_sign_PUBLICKEYBYTES];
    u_char sec_sign_key[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pub_sign_key, sec_sign_key);

    u_char pub_enc_key[crypto_box_PUBLICKEYBYTES];
    u_char sec_enc_key[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(pub_enc_key, sec_enc_key);
    clamp_and_reverse_seckey(sec_enc_key);

    if ((create_iron_dirs() == 0) &&
            (copy_ssh_key_files(pub_key_path) == 0)) {
        u_char sign_key_fp[GPG_KEY_FP_LEN];
        u_char enc_key_fp[GPG_KEY_FP_LEN];

        const char * uid = get_uid();
        char passphrase[PPHRASE_LEN];
        if ((write_public_key_file(pub_sign_key, sec_sign_key, pub_enc_key, uid, sign_key_fp, enc_key_fp) == 0) &&
                (generate_gpg_passphrase(passphrase) == 0) &&
                (write_secret_key_files(pub_sign_key, sec_sign_key, pub_enc_key, sec_enc_key, passphrase) == 0) &&
                (write_gpg_trustdb_file(sign_key_fp, uid) == 0) &&
                (write_pubkey_file(pub_sign_key, sign_key_fp, pub_enc_key, enc_key_fp) == 0)) {
            printf("\n"
                   "Generated new keys that will be used to transparently secure any file that\n"
                   "you upload ('put') or download ('get'). The new keys are compatible with GPG\n"
                   "v 2.1.14 and newer. They are protected with the passphrase\n"
                   "    %s\n\n"
                   "You will need this passphrase if you want to decrypt any '%s' files\n"
                   "directly with GPG. No need to store it, though - it is generated using\n"
                   "your SSH identity, so you can use the iron-passphrase utility to generate\n"
                   "it at any time.\n\n",
                   passphrase, IRON_SECURE_FILE_SUFFIX);
            retval = 0;
        }
    }

    return retval;
}

/**
 *  Upgrade ironcore key files using RSA key as signing key
 *
 *  Create a new ed25519 key pair, then rewrite the pubring.gpg file and trustdb.gpg files with the new data.
 *  Write a new secret key file for the ed25519 key, and update the ironpubring file to add the ed25519 key
 *  (but retain the RSA public key).
 *
 *  @param key_file 
 */
static int upgrade_key_files(FILE * key_file, const gpg_packet * pubkey_pkt)
{
    int retval = -1;
    gpg_packet * uid_pkt      = get_gpg_packet(key_file);
    const char * uid          = sshbuf_ptr(uid_pkt->data);
    gpg_packet * subkey_pkt   = get_gpg_curve25519_subkey_packet(key_file);
    u_char pub_enc_key[crypto_box_PUBLICKEYBYTES];

    //  First, copy ~/.ssh/ironcore/id_rsa to ~/.ssh/ironcore/id_iron, id_rsa.pub to id_iron.pub
    char pub_key_path[PATH_MAX];
    snprintf(pub_key_path, sizeof(pub_key_path), "%sid_rsa", iron_user_ironcore_dir());
    if (copy_ssh_key_files(pub_key_path) != 0)  return -1;
    

    if (extract_gpg_curve25519_pubkey(subkey_pkt->data, pub_enc_key) == crypto_box_PUBLICKEYBYTES) {
        char key_file_name[PATH_MAX];
        snprintf(key_file_name, PATH_MAX, "%s%s", iron_user_ironcore_dir(), GPG_PUBLIC_KEY_FNAME);

        char tmp_file_name[PATH_MAX];
        snprintf(tmp_file_name, PATH_MAX, "%s.orig", key_file_name);

        if (rename(key_file_name, tmp_file_name) == 0) {
            u_char pub_sign_key[crypto_sign_PUBLICKEYBYTES];
            u_char sec_sign_key[crypto_sign_SECRETKEYBYTES];
            crypto_sign_keypair(pub_sign_key, sec_sign_key);

            u_char sign_key_fp[GPG_KEY_FP_LEN];
            char   passphrase[PPHRASE_LEN];

            if ((rewrite_public_key_file(pub_sign_key, sec_sign_key, subkey_pkt, uid, sign_key_fp) == 0) &&
                    (generate_gpg_passphrase(passphrase) == 0) &&
                    (write_secret_key_files(pub_sign_key, sec_sign_key, NULL, NULL, passphrase) == 0) &&
                    (write_gpg_trustdb_file(sign_key_fp, uid) == 0) &&
                    (update_pubkey_file(pub_sign_key, sign_key_fp) == 0)) {
                retval = 0;
            }
        } else {
            error("Unable to rename %s to %s - %s", key_file_name, tmp_file_name, strerror(errno));
        }
    }
    sshbuf_free(uid_pkt->data);
    free(uid_pkt);
    sshbuf_free(subkey_pkt->data);
    free(subkey_pkt);

    return retval;
}

/**
 *  Check to see if the signing key is RSA
 *
 *  Check the Public Key packet in ~/.ssh/ironcore/pubring.gpg. If it is an RSA key, we need to upgrade the
 *  keys. We will create a new pubring.gpg file, generate the new Ed25519 key, write the public key packet,
 *  copy the UID packet from the old pubring.gpg, sign 
 *
 *  Also copy ~/.ssh/ironcore/id_rsa to id_iron, id_rsa.pub to id_iron.pub.
 *
 *  @return 0 if successful, negative number if error
 */
static int
upgrade_keys_if_required()
{
    int retval = -1;
    FILE * pubkey_file = open_pubkey_file();
    if (pubkey_file != NULL) {
        gpg_packet * pubkey_pkt = get_gpg_pub_key_packet(pubkey_file);
        if (pubkey_pkt != NULL) {
            const u_char * ptr = sshbuf_ptr(pubkey_pkt->data);
            ptr++;          //  Skip version #
            ptr += 4;       //  Skip creation timestamp

            if (((gpg_pk_algo) *ptr) == GPG_PKALGO_RSA_ES) {
                retval = upgrade_key_files(pubkey_file, pubkey_pkt);
                //  Need to convert files
            } else retval = 0;                          //  No conversion needed

            sshbuf_free(pubkey_pkt->data);
            free(pubkey_pkt);
        }

        fclose(pubkey_file);
    }

    return retval;
}

/**
 *  Confirm that public and private key files are in place for the current user.
 *
 *  Check to see if the public/private key files containing the specified login's ed25519 & cv25519 keys
 *  exist and are accessible.
 *
 *  If the key files are in place, check to see if they need to be updated. The first version of ironsftp
 *  used an RSA key for signing, but we now use an ed25519 key.  If the key files use RSA, convert.
 *
 *  @return int 1 if keys in place, 0 if not, -1 if error
 */
int
iron_check_keys(void)
{
    if (iron_initialize() != 0) return -1;

    int retval = -1;
    char file_name[PATH_MAX];
    snprintf(file_name, PATH_MAX, "%s%s", iron_user_ironcore_dir(), GPG_PUBLIC_KEY_FNAME);

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

    if (retval > 0) {
        if (upgrade_keys_if_required() != 0) retval = -1;
    }

    return retval;
}

/**
 *  Retrieve secret part of ed25519 signing key pair.
 *
 *  Retrieve the secret ed25519 signing key for the login that is running the process. Given the public
 *  keys for that user, compute the keygrip, open the secret key file, then retrieve the secret key. This
 *  requires the passphrase, which requires the SSH public key as well (it is used to generate the passphrase).
 *
 *  @param pub_keys public ssh and ed25519 keys - uses ed25519 key to generate keygrip, ssh key for passphrase
 *  @param sec_key Place to put secret part of ed25519 key (at least crypto_sign_SECRETKEYBYTES bytes)
 *  @return int num bytes in sec_key if successful, negative number if error
 */
int
get_gpg_secret_signing_key(const gpg_public_key * pub_keys, u_char * sec_key)
{
    static u_char cached_sec_key[crypto_sign_SECRETKEYBYTES];
    static size_t cached_sec_key_len = 0;

    if (cached_sec_key_len > 0) {
        memcpy(sec_key, cached_sec_key, cached_sec_key_len);
        return cached_sec_key_len;
    }
    
    int retval = -1;
    FILE * infile = open_ed25519_seckey_file("r", pub_keys->sign_key);
    if (infile != NULL) {
        u_char buf[4096];

        int num_read = fread(buf, 1, sizeof(buf), infile);
        retval = extract_gpg_ed25519_seckey(buf, num_read, pub_keys->sign_key, sec_key);
        if (retval > 0) {
            cached_sec_key_len = retval;
            memcpy(cached_sec_key, sec_key, retval);
        }
        fclose(infile);
    }

    return retval;
}

/**
 *  Retrieve secret part of cv25519 encryption key pair.
 *
 *  Retrieve the secret curve25519 encryption key for the login that is running the process. Given the public
 *  keys for that user, compute the keygrip, open the secret key file, then retrieve the secret key. This
 *  requires the passphrase, which requires the SSH public key as well (it is used to generate the passphrase).
 *
 *  @param pub_keys public ed25519 & cv25519 keys - uses cv25519 key to generate keygrip
 *  @param sec_key Place to put secret part of curve25519 key (at least crypto_box_SECRETKEYBYTES)
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
    FILE * infile = open_curve25519_seckey_file("r", pub_keys->enc_key);
    if (infile != NULL) {
        u_char buf[4096];

        int num_read = fread(buf, 1, sizeof(buf), infile);
        retval = extract_gpg_curve25519_seckey(buf, num_read, sec_key);
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
//  that key ID. The line contains the type of key (e.g. iron-ed25519), ": ", and
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
 *  @param key_type Either "ed25519" or "cv25519", currently
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
 *  Given a login's public keys (Ed25519, Cv25519 , and maybe RSA), write the index files that map the key IDs
 *  to the user's pubkey files.
 *
 *  @param keys Public key structure to index
 *  @return int 0 if successful, negative number if problem
 */
int
iron_index_public_keys(gpg_public_key * keys)
{
    int retval = 0;

    if (*keys->sign_fp) retval = index_public_key(GPG_KEY_ID_FROM_FP(keys->sign_fp), keys->login, "ed25519");
    if (retval == 0 && *keys->enc_fp) {
        retval = index_public_key(GPG_KEY_ID_FROM_FP(keys->enc_fp), keys->login, "cv25519");
    }
    if (retval == 0 && *keys->rsa_fp) {
        retval = index_public_key(GPG_KEY_ID_FROM_FP(keys->rsa_fp), keys->login, "rsa");
    }

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
        if (read_pubkey_file(keys) < 0) {
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

    strlcpy(keys.login, login, IRON_MAX_LOGIN_LEN);
    if (get_gpg_public_keys(login, &keys) == 0) {
        iron_index_public_keys(&keys);
        retval = 0;
    }

    return retval;
}
