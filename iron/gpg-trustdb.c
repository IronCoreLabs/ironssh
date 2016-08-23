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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "openssl/ripemd.h"

#include "iron-gpg.h"
#include "iron/gpg-internal.h"
#include "iron/gpg-trustdb.h"
#include "iron/util.h"


#define GPG_TRUSTDB_FNAME       "trustdb.gpg"
#define GPG_TRUSTDB_VER                 3

#define GPG_TRUST_MASK                  15
#define GPG_TRUST_UNKNOWN               0  /* o: not yet calculated/assigned */
#define GPG_TRUST_EXPIRED               1  /* e: calculation may be invalid */
#define GPG_TRUST_UNDEFINED             2  /* q: not enough information for calculation */
#define GPG_TRUST_NEVER                 3  /* n: never trust this pubkey */
#define GPG_TRUST_MARGINAL              4  /* m: marginally trusted */
#define GPG_TRUST_FULLY                 5  /* f: fully trusted      */
#define GPG_TRUST_ULTIMATE              6  /* u: ultimately trusted */
/* Trust values not covered by the mask. */
#define GPG_TRUST_FLAG_REVOKED          32 /* r: revoked */
#define GPG_TRUST_FLAG_SUB_REVOKED      64 /* r: revoked but for subkeys */
#define GPG_TRUST_FLAG_DISABLED         128 /* d: key/uid disabled */


#define GPG_TRUST_RECTYPE_VER           1
#define GPG_TRUST_RECTYPE_HTBL          10
#define GPG_TRUST_RECTYPE_HLIST         11
#define GPG_TRUST_RECTYPE_TRUST         12
#define GPG_TRUST_RECTYPE_VALID         13
#define GPG_TRUST_RECTYPE_FREE          254


#define GPG_TRUST_MODEL_CLASSIC         0
#define GPG_TRUST_MODEL_PGP             1
#define GPG_TRUST_MODEL_EXTERNAL        2
#define GPG_TRUST_MODEL_ALWAYS          3
#define GPG_TRUST_MODEL_DIRECT          4
#define GPG_TRUST_MODEL_AUTO            5
#define GPG_TRUST_MODEL_TOFU            6
#define GPG_TRUST_MODEL_TOFU_PGP        7


#define GPG_TRUST_DFLT_COMPLETES        1
#define GPG_TRUST_DFLT_MARGINALS        3
#define GPG_TRUST_DFLT_CERT_DEPTH       5
#define GPG_TRUST_DFLT_MIN_CERT         2


#define GPG_TRUST_REC_SIZE              40
#define GPG_TRUST_MIN_HTBL_SIZE         256
#define GPG_TRUST_HTBL_ITEMS_PER_REC    9


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
            tdb_rec[byte_idx] = 0x00;       // Restore "empty" record
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
    *recp = GPG_TRUST_RECTYPE_VER;      recp++;
    strcpy(recp, "gpg");                recp += 3;
    *recp = GPG_TRUSTDB_VER;            recp++;
    *recp = GPG_TRUST_DFLT_MARGINALS;   recp++;
    *recp = GPG_TRUST_DFLT_COMPLETES;   recp++;
    *recp = GPG_TRUST_DFLT_CERT_DEPTH;  recp++;
    *recp = GPG_TRUST_MODEL_PGP;        recp++;
    *recp = GPG_TRUST_DFLT_MIN_CERT;    recp++;
    /*  Skip reserved  */               recp += 2;
    iron_int_to_buf(iron_gpg_now(), recp);  recp += 4;
    /*  Leave next check 0  */          recp += 4;
    /*  Skip reserved  */               recp += 8;
    /*  Leave first free 0  */          recp += 4;
    /*  Skip reserved  */               recp += 4;
    iron_int_to_buf(1, recp);           /*  Rec # of start of hash table is 1  */
}

/**
 *  Generate the "trust" packet for trustDB file.
 *
 *  @param rec Place to write generated packet (at least key_len + 10 bytes)
 *  @param key Byte array with public key being added to DB
 *  @param key_len Num bytes in key
 *  @param next_rec index of the record following hash table where trust packet will go
 */
static void
generate_gpg_trustdb_trust(u_char * rec, const u_char * key, int key_len, int next_rec)
{
    u_char * recp = rec;

    bzero(rec, GPG_TRUST_REC_SIZE);
    *recp = GPG_TRUST_RECTYPE_TRUST;   recp++;
    /*  Skip reserved  */              recp++;
    memcpy(recp, key, key_len);        recp += key_len;
    *recp = GPG_TRUST_ULTIMATE;        recp++;
    /*  Leave depth 0 */               recp++;
    /*  Leave min owner trust 0 */     recp++;
    /*  Skip reserved  */              recp++;
    iron_int_to_buf(next_rec, recp);
}

/**
 *  Generate the "valid" packet for trustDB file.
 *
 *  @param rec Place to write generated packet (at least 28 bytes)
 *  @param uid String identifying user (typically "Name <emailaddr>")
 */
static void
generate_gpg_trustdb_valid(u_char * rec, const char * uid)
{
    u_char * recp = rec;

    bzero(rec, GPG_TRUST_REC_SIZE);
    *recp = GPG_TRUST_RECTYPE_VALID;   recp++;
    /*  Skip reserved  */              recp++;
    
    /* Compute the RIPE-MD160 hash of the UID. Yes, RIPE-MD160. Thanks, GPG. */
    u_char hash[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160_CTX ctx;
    RIPEMD160_Init(&ctx);
    RIPEMD160_Update(&ctx, uid, strlen(uid));
    RIPEMD160_Final(hash, &ctx);

    memcpy(recp, hash, sizeof(hash));  recp += sizeof(hash);
    *recp = GPG_TRUST_ULTIMATE;        recp++;  //  Validity
    /*  Leave next rec 0 */            recp += 4;
    /*  Leave full count 0 */          recp++;
    /*  Leave marginal count 0 */
}

/**
 *  Generate contents of trustDB and write file.
 *
 *  Create the trustdb.gpg file and write it under the specified .ssh directory.
 *
 *  @param key Public key to add trust
 *  @param key_len Num bytes in key
 *  @param uid String identifying user (typically "Name <emailaddr>")
 *  @return int 0 if successful, negative number if error
 */
int
write_gpg_trustdb_file(const u_char * key, size_t key_len, const char * uid)
{
    int retval = -1;

    char file_name[PATH_MAX];
    snprintf(file_name, PATH_MAX, "%s%s", iron_user_ssh_dir(), GPG_TRUSTDB_FNAME);
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
