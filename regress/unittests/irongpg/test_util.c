#include "regress/unittests/test_helper/test_helper.h"

#include "iron/util.c"


void
test_str2hex(void)
{
    TEST_START("str2hex");

    u_char hex1[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

    char hstr[32];

    iron_hex2str(hex1, sizeof(hex1), hstr);
    ASSERT_STRING_EQ(hstr,"0123456789ABCDEF"); 

    iron_hex2str(hex1, 0, hstr);
    ASSERT_STRING_EQ(hstr, "");

    u_char hex[16];
    int retval = iron_str2hex("0123456789ABCDEF", hex, sizeof(hex));
    ASSERT_INT_EQ(retval, 8);
    ASSERT_INT_EQ(memcmp(hex, hex1, retval), 0);

    retval = iron_str2hex("0123456789ABCDEF0123456789ABCDEF0123456789", hex, sizeof(hex));
    ASSERT_INT_EQ(retval, -1);

    //  Invalid char
    retval = iron_str2hex("ABCDEFG", hex, sizeof(hex));
    ASSERT_INT_EQ(retval, -1);

    //  Odd number of chars
    retval = iron_str2hex("ABCDE", hex, sizeof(hex));
    ASSERT_INT_EQ(retval, -1);

    TEST_DONE();
}

void
test_int_to_buf(void)
{
    TEST_START("int2buf");

    u_char buf1[4] = { 0x01, 0x23, 0x45, 0x67 };
    u_char buf2[4] = { 0xf0, 0x01, 0x02, 0x03 };

    u_char buf[4];
    iron_int_to_buf(19088743, buf);
    ASSERT_INT_EQ(memcmp(buf1, buf, 4), 0);

    iron_int_to_buf(4026597891, buf);
    ASSERT_INT_EQ(memcmp(buf2, buf, 4), 0);

    u_int32_t ival;
    ival = iron_buf_to_int(buf1);
    ASSERT_INT_EQ(ival, 19088743);

    ival = iron_buf_to_int(buf2);
    ASSERT_INT_EQ(ival, 4026597891);

    TEST_DONE();
}

/*  Read a multi-precision integer of the format used in GPG (two bytes containing the
 *  length in bits, MSB-first, followed by the bits, MSB first, padded with leading zero bits
 *  to full octets) and convert it into an OpenSSL BIGNUM.
 */
static int
get_bignum(struct sshbuf * buf, BIGNUM * bignum)
{
    int retval = -1;

    u_int16_t len;

    u_char tmp[1024];
    sshbuf_get_u16(buf, &len);
    int num_bytes = (len + 7) / 8;

    if (sshbuf_get(buf, tmp, num_bytes) == 0) {
        BN_bin2bn(tmp, num_bytes, bignum);
        retval = 0;
    }

    return retval;
}

void
test_bignums(void)
{
    TEST_START("bignums");

    static u_char bn1[] = { 0x00, 0x06, 0x23 };
    static u_char bn2[] = { 0x00, 0x08, 0xa5 };
    static u_char bn3[] = { 0x00, 0x15, 0x12, 0x34, 0x56 };
    static u_char bn4[] = {
        0x01, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff
    };


    typedef struct bndata {
        u_char * bndata;
        size_t   bndata_len;
        int      num_bits;
    } bndata;

    bndata test_item[] = {
        { bn1, sizeof(bn1), 6 },
        { bn2, sizeof(bn2), 8 },
        { bn3, sizeof(bn3), 21 },
        { bn4, sizeof(bn4), 256 }
    };


    struct sshbuf * bn_buf = sshbuf_new();
    BIGNUM * bn = BN_new();
    for (size_t i = 0; i < sizeof(test_item) / sizeof(bndata); i++) {
        BN_bin2bn(test_item[i].bndata + 2, test_item[i].bndata_len - 2, bn);
        iron_put_bignum(bn_buf, bn);
    }

    u_char tmp[64];
    for (size_t i = 0; i < sizeof(test_item) / sizeof(bndata); i++) {
        int retval = get_bignum(bn_buf, bn);
        ASSERT_INT_EQ(retval, 0);
        ASSERT_INT_EQ(BN_num_bits(bn), test_item[i].num_bits);
        int len = BN_bn2bin(bn, tmp);
        ASSERT_INT_EQ(len, test_item[i].bndata_len - 2);
        ASSERT_INT_EQ(memcmp(tmp, test_item[i].bndata + 2, len), 0);
    }

    sshbuf_free(bn_buf);
    BN_free(bn);

    TEST_DONE();
}

void
test_put_num_sexpr(void)
{
    TEST_START("put_num_sexpr");

    u_char b1[] = { 0x00 };
    u_char b2[] = { 0xff };
    u_char b3[] = { 0x80,
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

    struct sshbuf * sb = sshbuf_new();

    iron_put_num_sexpr(sb, b1, sizeof(b1));
    ASSERT_INT_EQ(sshbuf_len(sb), 3);
    ASSERT_INT_EQ(memcmp(sshbuf_ptr(sb), "1:", 2), 0);
    ASSERT_INT_EQ(memcmp(sshbuf_ptr(sb) + 2, b1, sizeof(b1)), 0);

    sshbuf_reset(sb);
    iron_put_num_sexpr(sb, b2, sizeof(b2));
    ASSERT_INT_EQ(sshbuf_len(sb), 4);
    ASSERT_INT_EQ(memcmp(sshbuf_ptr(sb), "2:", 2), 0);
    ASSERT_INT_EQ(*(sshbuf_ptr(sb) + 2), 0);
    ASSERT_INT_EQ(*(sshbuf_ptr(sb) + 3), b2[0]);

    sshbuf_reset(sb);
    iron_put_num_sexpr(sb, b3, sizeof(b3));
    ASSERT_INT_EQ(sshbuf_len(sb), sizeof(b3) + 4);
    ASSERT_INT_EQ(memcmp(sshbuf_ptr(sb), "18:", 3), 0);
    ASSERT_INT_EQ(*(sshbuf_ptr(sb) + 3), 0);
    ASSERT_INT_EQ(memcmp(sshbuf_ptr(sb) + 4, b3, sizeof(b3)), 0);

    sshbuf_free(sb);

    TEST_DONE();
}

void
test_reverse_barray(void)
{
    TEST_START("reverse_byte_array");

    u_char be[]   = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    u_char be_r[] = { 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01 };
    u_char bo[]   = { 0x01, 0x23, 0x45, 0x67, 0xff, 0x89, 0xab, 0xcd, 0xef };
    u_char bo_r[] = { 0xef, 0xcd, 0xab, 0x89, 0xff, 0x67, 0x45, 0x23, 0x01 };
                    
    u_char b[9];

    iron_reverse_byte_array(be, b, sizeof(be));
    ASSERT_INT_EQ(memcmp(b, be_r, sizeof(be_r)), 0);
    iron_reverse_byte_array(bo, b, sizeof(bo));
    ASSERT_INT_EQ(memcmp(b, bo_r, sizeof(bo_r)), 0);

    iron_reverse_byte_array_in_place(be, sizeof(be));
    ASSERT_INT_EQ(memcmp(be, be_r, sizeof(be_r)), 0);
    iron_reverse_byte_array_in_place(bo, sizeof(bo));
    ASSERT_INT_EQ(memcmp(bo, bo_r, sizeof(bo_r)), 0);

    TEST_DONE();
}

void
test_sha1(void)
{
    TEST_START("compute_sha1_hash");

    u_char * b = "This is a test. It is only a test. If it had been a real emergency, there would be smoke.\n";

    u_char exp[] = { 0x66, 0x4f, 0x72, 0x1e, 0xdc, 0x4e, 0x93, 0x0c, 0xf5, 0xfa,
                     0x9f, 0x6e, 0x5c, 0x78, 0xe3, 0xf5, 0xf5, 0x09, 0x2e, 0x6f };

    u_char hash[SHA_DIGEST_LENGTH];

    iron_compute_sha1_hash_chars(b, strlen(b), hash);
    ASSERT_INT_EQ(memcmp(hash, exp, sizeof(hash)), 0);

    struct sshbuf * sb = sshbuf_from(b, strlen(b));

    iron_compute_sha1_hash_sshbuf(sb, hash);
    ASSERT_INT_EQ(memcmp(hash, exp, sizeof(hash)), 0);

    sshbuf_free(sb);

    TEST_DONE();
}

//======================================================================================================
//  Elected to skip unit tests for iron_hashcrypt and iron_compute_rsa_signature, since they are just
//  wrappers for the openssl functions.
//======================================================================================================

void
test_iron_extension_offset(void)
{
    TEST_START("iron_extension_offset");

    int retval = iron_extension_offset("abc.iron");
    ASSERT_INT_EQ(retval, 3);
    retval = iron_extension_offset("abcdefg");
    ASSERT_INT_EQ(retval, -1);
    retval = iron_extension_offset("a");
    ASSERT_INT_EQ(retval, -1);

    TEST_DONE();
}
