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

#ifndef _IRON_COMMON_H
#define _IRON_COMMON_H

/* Names of the extensions for secure sharing and the ICL identity servers. Value of the first extension is the
 * version number.
 */
#define ICL_SECURE_SHARING_EXT		"secureSharing@ironcorelabs.com"
#define ICL_SECURE_SHARING_VER		"1"
#define ICL_IDENTITY_SERVERS_EXT	"identityServers@ironcorelabs.com"

/* Suffix for files that have been encrypted and shared. */
#define ICL_SECURE_FILE_SUFFIX		".iron"
#define ICL_SECURE_FILE_SUFFIX_LEN	5		//  strlen(ICL_SECURE_FILE_SUFFIX)

/* UTF8 character that looks like a padlock, followed by a space */
#define ICL_LOCK_ICON			"\xf0\x9f\x94\x92 "


int	 iron_extension_offset(const char * name);

#endif  /* _IRON_COMMON_H */
