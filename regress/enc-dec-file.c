#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include "includes.h"
#include "iron-gpg.h"

char * user_login;

int
main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "\nUsage: %s <infile>\n\n", argv[0]);
		return -1;
	}

	struct passwd * user_pw = getpwuid(getuid());
	if (user_pw == NULL) {
		fprintf(stderr, "Unable to determine current user's login\n\n");
	} else {
		user_login = strdup(user_pw->pw_name);
	}

	if (check_iron_keys(user_login) != 0) {
		fprintf(stderr, "Unable to find or create the necessary keys for current user's login\n\n");
		return -2;
	}
	
	char new_fname[PATH_MAX + 1];
	snprintf(new_fname, PATH_MAX, "%s_XXXX", argv[1]);
	int fd = mkstemp(new_fname);
	if (fd < 0) {
		fprintf(stderr, "Unable to create temporary file name\n\n");
		return -3;
	}

	unlink(new_fname);
	if (link(argv[1], new_fname) < 0) {
		fprintf(stderr, "Unable to create temporary link to file %s\n\n", argv[1]);
		return -4;
	}
	close(fd);

	char enc_fname[PATH_MAX + 1];
	int outfd = write_gpg_encrypted_file(new_fname, 0, enc_fname);
	if (outfd < 0) {
		fprintf(stderr, "Unable to write encrypted file for input file %s\n\n", argv[1]);
		return -5;
	}

	close(outfd);
	unlink(new_fname);
	char dec_fname[PATH_MAX + 1];
	int decfd = write_gpg_decrypted_file(user_login, enc_fname, dec_fname);
	if (decfd < 0) {
		fprintf(stderr, "Unable to write decrypted file for input file %s\n\n", argv[1]);
		return -6;
	}
	close(decfd);

	char cmp_cmd[512];
	snprintf(cmp_cmd, 511, "cmp %s %s", argv[1], new_fname);
	if (system(cmp_cmd) != 0) {
		fprintf(stderr, "decrypted file did not match original input file %s\n\n", argv[1]);
		return -7;
	}
	if (unlink(enc_fname) < 0) {
		fprintf(stderr, "unable to unlink %s\n\n", enc_fname);
	}
	if (unlink(dec_fname) < 0) {
		fprintf(stderr, "unable to unlink %s\n\n", dec_fname);
	}

	return 0;
}
