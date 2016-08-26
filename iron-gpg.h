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
