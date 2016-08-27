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
#include "log.h"
#include "iron/gpg-internal.h"
#include "iron/gpg-keyfile.h"
#include "iron/recipient.h"


//================================================================================
//  Functions to manipulate list of registered recipients - the users with which
//  an uploaded file will be shared.  We have imposed a somewhat arbitrary limit
//  of 10 recipients (in addition to the current user) for file sharing.
//
//  The first entry in the list is always the current user, and that entry will
//  always be in the list.
//================================================================================

static gpg_public_key recipient_list[IRON_MAX_RECIPIENTS];
static int num_recipients = 0;

/**
 *  Return current registered recipient list.
 *
 *  Return a pointer to the current list of registered recipients. If the list is empty, create it and
 *  put the current user into the list.
 *
 *  @param recip_list Place to write the pointer to the recipient list
 *  @return int Num recipients in list, or negative number if error (unable to initialize list)
 */
int
iron_get_recipients(const gpg_public_key ** recip_list)
{
    if (num_recipients == 0) {
        //  The current user is always included in the recipient list, so get that entry added.
        if (iron_add_recipient(iron_user_login()) != 0) {
            *recip_list = NULL;
            return -1;
        }
    }

    *recip_list = recipient_list;
    return num_recipients;
}

/**
 *  Return the entry for a specific user.
 *
 *  The recipient entry has all the user's public key information.
 *
 *  @param login User whose entry to fetch
 *  @returns const gpg_public_key * Pointer to entry for the user, NULL if keys couldn't be retrieved
 */
const gpg_public_key *
iron_get_recipient_keys(const char * login)
{
    //  High tech linear search of recipient list. It should be short - don't freak out.
    const gpg_public_key * recip;
    int num_recip = iron_get_recipients(&recip);
    int ct = 0;
    while (ct < num_recip && strcmp(login, recip->login) != 0) {
        recip++;
        ct++;
    }

    if (ct == num_recip) recip = NULL;
    return recip;
}

/**
 *  Return the entry for a specific key ID.
 *
 *  The recipient entry has all the user's public key information. It will return the first entry that
 *  matches the key ID in either the cv25519 or the RSA key ID.
 *
 *  @param key_id ID whose entry to fetch
 *  @returns const gpg_public_key * Pointer to entry for the user, NULL if keys couldn't be retrieved
 */
const gpg_public_key *
iron_get_recipient_keys_by_key_id(const char * key_id)
{
    //  Another linear search of recipient list - still no cause for alarm.
    const gpg_public_key * recip;
    int num_recip = iron_get_recipients(&recip);
    int ct = 0;
    while (ct < num_recip && memcmp(key_id, GPG_KEY_ID_FROM_FP(recip->fp), GPG_KEY_ID_LEN) != 0 &&
           memcmp(key_id, GPG_KEY_ID_FROM_FP(recip->signer_fp), GPG_KEY_ID_LEN) != 0) {
        recip++;
        ct++;
    }

    if (ct == num_recip) recip = NULL;
    return recip;
}

/**
 *  Add a recipient to registered list.
 *
 *  Add an entry for the specified user to the list of registered recipients. Requires that the user
 *  has a ~<login>/.pubkey file, or that we can access the user's ~<login>/.ssh/pubring.gpg file. (The
 *  latter probably only happens if the login is the user running the process.)
 *
 *  We have a lmit on the number that can be added - attempting to add one more is an error.
 *
 *  @param login User to add
 *  @return int 0 if successful, negative number if error
 */
int
iron_add_recipient(const char * login)
{
    int retval = 0;

    /*  In case this is called before anything else has accessed the list - we want to make sure that the
     *  first entry in the list is always the current user.
     */
    if (num_recipients == 0 && strcmp(login, iron_user_login()) != 0) iron_add_recipient(iron_user_login());

    for (int i = 0; i < num_recipients; i++) {
        if (strcmp(recipient_list[i].login, login) == 0) {
            error("User %s already in the recipient list.", login);
            retval = -1;
            break;
        }
    }

    if (retval == 0) {
        if (num_recipients < IRON_MAX_RECIPIENTS) {
            gpg_public_key * new_ent = recipient_list + num_recipients;
            strncpy(new_ent->login, login, IRON_MAX_LOGIN_LEN);
            new_ent->login[IRON_MAX_LOGIN_LEN] = 0;
            size_t key_len;
            bzero(&(new_ent->rsa_key), sizeof(new_ent->rsa_key));
            new_ent->rsa_key.type = KEY_RSA;
            new_ent->rsa_key.ecdsa_nid  = -1;
            if (get_gpg_public_keys(login, &(new_ent->rsa_key), new_ent->signer_fp, new_ent->key, &key_len,
                                    new_ent->fp) == 0) {
                if (strcmp(login, iron_user_login()) != 0) iron_index_public_keys(new_ent);
                num_recipients++;
            } else {
                error("Unable to retrieve public key information for user %s", login);
                retval = -1;
            }
        } else {
            error("Recipient list is full - cannot add more.");
            retval = -1;
        }
    }

    return retval;
}

/**
 *  Remove a recipient from registered list.
 *
 *  Remove the entry for the specified user from the list of registered recipients. Cannot remove the current
 *  user.
 *
 *  @param login User to remove
 *  @return int 0 if successful, negative number if error
 */
int
iron_remove_recipient(const char * login)
{
    if (iron_initialize() != 0) return -1;

    int retval = -1;

    if (strcmp(login, iron_user_login()) == 0) {
        error("Current user (%s) cannot be removed from the recipient list. Ignored.", login);
    } else {
        int i;
        //  Skip the first entry, which is the current user.
        for (i = 1; i < num_recipients; i++) {
            if (strcmp(recipient_list[i].login, login) == 0) {
                retval = 0;
                break;
            }
        }

        if (retval == 0) {
            if (i != num_recipients - 1) {
                memmove(recipient_list + i, recipient_list + i + 1, num_recipients - i - 1);
            }
            num_recipients--;
        } else {
            error("User %s not found in the recipient list.", login);
        }
    }

    return retval;
}

/**
 *  Reset the registered list.
 *
 *  Empty out the list of registered recipients, except for the first entry, which should be the current
 *  user's entry. That one should always be in the list.
 */
void
iron_clear_recipients(void)
{
    if (num_recipients >= 1) num_recipients = 1;
}

/**
 *  List the entries in the registered list.
 *
 *  For each of the entries (including the current user), display the login.
 */
void
iron_show_recipients(void)
{

    const gpg_public_key * recip_list;
    int rct = iron_get_recipients(&recip_list);
    if (rct >= 0) {
        logit("Currently registered recipients:");
        for (int i = 0; i < rct; i++) {
            logit("  %s", recip_list[i].login);
        }
    } else {
        error("Unable to retrieve list of recipients.");
    }
}
