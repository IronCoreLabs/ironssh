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

#ifndef _IRON_GPG_H
#define _IRON_GPG_H

#define IRON_ERR_NOT_ENCRYPTED  -101    //  Attempted to decrypt a file, but didn't find the GPG info we expected
#define IRON_ERR_NOT_FOR_USER   -102    //  File was encrypted, but not to the user retrieving it
#define IRON_ERR_NO_OVERWRITE   -103    //  File exists, and user doesn't want to overwrite

#define IRON_PUBKEY_FNAME       ".ironpubkey"   //  Name of the file in user's home dir that holds public key info


extern int  iron_initialize(void);
extern void iron_set_host(const char * hostname);
extern int  iron_check_keys(void);
extern int  iron_generate_keys(void);

extern const char * iron_host(void);
extern const char * iron_user_login(void);
extern const char * iron_user_ssh_dir(void);
extern const char * iron_user_ironcore_dir(void);
extern const char * iron_user_pubkey_file(void);
extern const char * iron_pubkey_file(const char * login);


extern int  write_gpg_encrypted_file(const char * fname, char * enc_fname);
extern int  write_gpg_decrypted_file(const char * fname, char * dec_fname);

extern void iron_clear_recipients(void);
extern void iron_show_recipients(void);
extern int  iron_add_recipient(const char * login);
extern int  iron_remove_recipient(const char * login);
extern int  iron_index_user(const char * login);
extern int  iron_extension_offset(const char * name);

#endif  /* _IRON_GPG_H */
