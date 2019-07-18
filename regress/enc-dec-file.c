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

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include "includes.h"
#include "iron-common.h"
#include "iron-gpg.h"


static char * __progname;

static void
usage(void)
{
    fprintf(stderr, "\nUsage: %s [-T test_dir] <infile>\n\n", __progname);
    exit(1);
}

int
main(int argc, char **argv)
{
    __progname = argv[0];

    if (argc < 2) {
        usage();
    }

    extern char * optarg;
    extern int    optind;
    char ch;
    while ((ch = getopt(argc, argv, "T:")) != -1) {
        switch (ch) {
            case 'T':
                iron_set_user(optarg);
                break;
            default:
                usage();
                break;
        }
    }

    if (optind == argc || argc > (optind + 1)) usage();
    char * in_name = argv[optind];

    if (strlen(in_name) > PATH_MAX - IRON_SECURE_FILE_SUFFIX_LEN - 6) {
        fprintf(stderr, "File name \"%s\" is too long.\n\n", in_name);
        return -2;
    }

    int keys_available = iron_check_keys();
    if (keys_available < 0 ||
            (keys_available == 0 && iron_generate_keys(NULL) < 0)) {
        fprintf(stderr, "Unable to find or create the necessary keys for current user's login\n\n");
        return -3;
    }

    //  Create a <infile>.iron file, so that write_gpg_encrypted_file will generate a different output file.
    char tmp_fname[PATH_MAX];
    sprintf(tmp_fname, "%s%s", in_name, IRON_SECURE_FILE_SUFFIX);
    FILE * tmp_file = fopen(tmp_fname, "w");
    fclose(tmp_file);

    char enc_fname[PATH_MAX];
    int outfd = write_gpg_encrypted_file(in_name, enc_fname);
    if (outfd < 0) {
        fprintf(stderr, "Unable to write encrypted file for input file \"%s\"\n\n", in_name);
        return -5;
    }
    close(outfd);

    char dec_fname[PATH_MAX];
    int decfd = write_gpg_decrypted_file(enc_fname, dec_fname);
    if (decfd < 0) {
        fprintf(stderr, "Unable to write decrypted file for input file \"%s\"\n\n", in_name);
        return -6;
    }
    close(decfd);

    char cmp_cmd[512];
    snprintf(cmp_cmd, 511, "cmp %s %s", in_name, dec_fname);
    int rv = system(cmp_cmd);
    if (rv != 0) {
        fprintf(stderr, "decrypted file did not match original input file \"%s\"\n\n", in_name);
    }
    if (unlink(tmp_fname) < 0) {
        fprintf(stderr, "unable to unlink \"%s\"\n\n", tmp_fname);
    }
    if (unlink(enc_fname) < 0) {
        fprintf(stderr, "unable to unlink \"%s\"\n\n", enc_fname);
    }
    if (unlink(dec_fname) < 0) {
        fprintf(stderr, "unable to unlink \"%s\"\n\n", dec_fname);
    }

    return rv;
}
