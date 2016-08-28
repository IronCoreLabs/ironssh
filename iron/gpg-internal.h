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

#ifndef _IRON_GPG_INTERNAL_H
#define _IRON_GPG_INTERNAL_H

#include "includes.h"

//  These key-related constants are used in files with intertwined dependencies, so they are pulled into here
//  to untangle.
#define GPG_MAX_KEY_SIZE        512             //  # bytes a secret or public key can occupy
#define GPG_KEY_FP_LEN          20              //  Bytes in key fingerprint - same as the SHA hash length
#define GPG_KEY_ID_LEN          8               //  Bytes in key ID - the last 8 bytes of the key fingerprint
#define GPG_KEY_ID_OFFSET       (GPG_KEY_FP_LEN - GPG_KEY_ID_LEN)       //  Offset from start of fingerprint for ID

//  If you have a key fingerprint, this macro gives you a pointer to the key ID that corresponds to the FP
#define GPG_KEY_ID_FROM_FP(fp) ((fp) + GPG_KEY_ID_OFFSET)

#define IRONCORE_SUBDIR         "ironcore/"     //  subdir of ~/.ssh that holds all IronCore files


extern u_int32_t    iron_gpg_now();

#endif
