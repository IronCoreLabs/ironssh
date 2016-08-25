#include "regress/unittests/test_helper/test_helper.h"
#include "xmalloc.h"

void test_bignums(void);
void test_int_to_buf(void);
void test_iron_extension_offset(void);
void test_packets(void);
void test_put_num_sexpr(void);
void test_reverse_barray(void);
void test_s2k(void);
void test_sha1(void);
void test_str2hex(void);
void test_tags(void);

void
tests(void)
{
    // Initialization
    ssh_malloc_init();

    test_str2hex();
    test_bignums();
    test_int_to_buf();
    test_put_num_sexpr();
    test_reverse_barray();
    test_sha1();
    test_iron_extension_offset();
    test_tags();
    test_packets();
    test_s2k();
}
