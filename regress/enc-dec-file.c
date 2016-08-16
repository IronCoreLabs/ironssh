#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include "includes.h"
#include "iron-common.h"
#include "iron-gpg.h"

int
main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "\nUsage: %s <infile>\n\n", argv[0]);
		return -1;
	}

	if (check_iron_keys() != 0) {
		fprintf(stderr, "Unable to find or create the necessary keys for current user's login\n\n");
		return -2;
	}
	
	//  Create a <infile>.iron file, so that write_gpg_encrypted_file will generate a different output file.
	char tmp_fname[PATH_MAX + 1];
	sprintf(tmp_fname, "%s%s", argv[1], IRON_SECURE_FILE_SUFFIX);
	FILE * tmp_file = fopen(tmp_fname, "w");
	fclose(tmp_file);

	char enc_fname[PATH_MAX + 1];
	int outfd = write_gpg_encrypted_file(argv[1], enc_fname);
	if (outfd < 0) {
		fprintf(stderr, "Unable to write encrypted file for input file %s\n\n", argv[1]);
		return -5;
	}
	close(outfd);

	char dec_fname[PATH_MAX + 1];
	int decfd = write_gpg_decrypted_file(enc_fname, dec_fname);
	if (decfd < 0) {
		fprintf(stderr, "Unable to write decrypted file for input file %s\n\n", argv[1]);
		return -6;
	}
	close(decfd);

	char cmp_cmd[512];
	snprintf(cmp_cmd, 511, "cmp %s %s", argv[1], dec_fname);
	int rv = system(cmp_cmd);
	if (rv != 0) {
		fprintf(stderr, "decrypted file did not match original input file %s\n\n", argv[1]);
	}
	if (unlink(tmp_fname) < 0) {
		fprintf(stderr, "unable to unlink %s\n\n", tmp_fname);
	}
	if (unlink(enc_fname) < 0) {
		fprintf(stderr, "unable to unlink %s\n\n", enc_fname);
	}
	if (unlink(dec_fname) < 0) {
		fprintf(stderr, "unable to unlink %s\n\n", dec_fname);
	}

	return rv;
}
