#include "regress/unittests/test_helper/test_helper.h"

#include "iron/gpg-key.c"


void
test_s2k(void)
{
    TEST_START("s2k");

    static unsigned char salt[S2K_SALT_BYTES] = { 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    const char * pphrase = "ImGumbyAndYouAreNot";

    static unsigned char expected_key1[AES128_KEY_BYTES] = {
        0x0e, 0xa5, 0x00, 0x1c, 0xce, 0xad, 0x7e, 0xa8, 0xa0, 0x81, 0x38, 0xae, 0xaf, 0x4e, 0x28, 0xd5
    };
    unsigned char s2k_key1[AES128_KEY_BYTES];

    compute_gpg_s2k_key(pphrase, sizeof(s2k_key1), salt, S2K_ITER_BYTE_COUNT, s2k_key1);
    ASSERT_INT_EQ(memcmp(s2k_key1, expected_key1, sizeof(s2k_key1)), 0);

    //  Second test to handle the case where we need to run multiple hashes to generate enough bits
    //  Note that the first 16 bytes are the same as the previous test - this is to be expected, since the
    //  salt and passphrase are the same, so the first hash is executed identically.
    static unsigned char expected_key2[48] = {
        0x0e, 0xa5, 0x00, 0x1c, 0xce, 0xad, 0x7e, 0xa8, 0xa0, 0x81, 0x38, 0xae, 0xaf, 0x4e, 0x28, 0xd5,
        0x21, 0xf1, 0xee, 0x4b, 0x02, 0xc0, 0x0f, 0x63, 0x6a, 0x17, 0xbf, 0x62, 0x34, 0x10, 0x26, 0x48,
        0x7b, 0xc6, 0x3f, 0x08, 0x9d, 0xb5, 0x6b, 0x34, 0x70, 0x3b, 0x71, 0xdb, 0x67, 0x92, 0x6f, 0x5f
    };
    unsigned char s2k_key2[48];

    compute_gpg_s2k_key(pphrase, sizeof(s2k_key2), salt, S2K_ITER_BYTE_COUNT, s2k_key2);
    ASSERT_INT_EQ(memcmp(s2k_key2, expected_key2, sizeof(s2k_key2)), 0);

    TEST_DONE();
}
