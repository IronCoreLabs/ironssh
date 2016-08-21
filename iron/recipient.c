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
#include "log.h"
#include "iron/gpg-internal.h"
#include "iron/gpg-keyfile.h"
#include "iron/recipient.h"


//================================================================================
//  Functions to manipulate list of registered recipients - the users with which
//  an uploaded file will be shared.  We have imposed a somewhat arbitrary limit
//  of 10 recipients (in addition to the current user) for file sharing.
//================================================================================

#define MAX_RECIPIENTS  11
static gpg_public_key recipient_list[11];
static int num_recipients = 0;

/**
 *  Return current registered recipient list.
 *
 *  Return a pointer to the current list of registered recipients. If the list is empty, create it and
 *  put the current user into the list.
 *
 *  @param recip_list Place to write the pointer to the recipient list.
 *  @return int Num recipients in list, or negative number if error (unable to initialize list)
 */
int
get_recipients(const gpg_public_key ** recip_list)
{
    if (num_recipients == 0) {
        //  The current user is always included in the recipient list, so get that entry added.
        if (add_recipient(iron_user_login()) != 0) {
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
get_recipient_keys(const char * login)
{
    //  High tech linear search of recipient list. It should be short - don't freak out.
    const gpg_public_key * recip;
    int num_recip = get_recipients(&recip);
    int ct = 0;
    while (ct < num_recip && strcmp(login, recip->login) != 0) {
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
add_recipient(const char * login)
{
    int retval = 0;
    for (int i = 0; i < num_recipients; i++) {
        if (strcmp(recipient_list[i].login, login) == 0) {
            error("User %s already in the recipient list.", login);
            retval = -1;
            break;
        }
    }

    if (retval == 0) {
        if (num_recipients < MAX_RECIPIENTS) {
            gpg_public_key * new_ent = recipient_list + num_recipients;
            strncpy(new_ent->login, login, IRON_MAX_LOGIN_LEN);
            new_ent->login[IRON_MAX_LOGIN_LEN] = 0;
            size_t key_len;
            bzero(&(new_ent->rsa_key), sizeof(new_ent->rsa_key));
            new_ent->rsa_key.type = KEY_RSA;
            new_ent->rsa_key.ecdsa_nid  = -1;
            if (get_gpg_public_keys(login, &(new_ent->rsa_key), new_ent->signer_fp, new_ent->key, &key_len,
                                new_ent->fp) == 0) {
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
 *  Remove the entry for the specified user from the list of registered recipients.
 *
 *  @param login User to remove
 *  @return int 0 if successful, negative number if error
 */
int
remove_recipient(const char * login)
{
    if (iron_initialize() != 0) return -1;

    int retval = -1;

    if (strcmp(login, iron_user_login()) == 0) {
        error("Current user (%s) cannot be removed from the recipient list. Ignored.", login);
    } else {
        int i;
        for (i = 0; i < num_recipients; i++) {
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
 *  Empty out the list of registered recipients. The next time it is accessed, it should be repopulated
 *  with the current user's entry.
 */
void
reset_recipients()
{
    num_recipients = 0;
}

