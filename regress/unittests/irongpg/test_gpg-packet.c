#include "regress/unittests/test_helper/test_helper.h"

#include "iron/gpg-packet.c"

typedef struct tdata {
    unsigned char * h;
    size_t h_len;
    gpg_tag tag;
    ssize_t size;
} tdata;

static void
do_tag_and_size(const tdata * td)
{
    unsigned char hdr[8];
    int retval;
    gpg_tag tag;
    ssize_t size;

    retval = extract_gpg_tag_and_size(td->h, &tag, &size);
    ASSERT_INT_EQ(retval, td->h_len);
    ASSERT_INT_EQ(tag, td->tag);
    ASSERT_INT_EQ(size, td->size);

    retval = generate_gpg_tag_and_size(tag, size, hdr);
    ASSERT_INT_EQ(retval, td->h_len);
    ASSERT_INT_EQ(memcmp(hdr, td->h, retval), 0);
}

static void
do_read_tag_and_size(FILE * infile, const tdata * td)
{
    int retval;
    gpg_tag tag;
    ssize_t size;

    retval = get_gpg_tag_and_size(infile, &tag, &size);
    ASSERT_INT_EQ(retval, 0);
    ASSERT_INT_EQ(tag, td->tag);
    ASSERT_INT_EQ(size, td->size);
}

void
test_tags()
{
    TEST_START("tag_and_len");

    unsigned char h0[] = {0x84, 0x00};
    unsigned char h1[] = {0x88, 0x01};
    unsigned char h2[] = {0x8d, 0x12, 0x34};
    unsigned char h3[] = {0x92, 0xfe, 0xdc, 0xba, 0x98};
    unsigned char h4[] = {0x97};
    unsigned char h5[] = {0xd1, 0x23};
    unsigned char h6[] = {0xd2, 0xc1, 0x23};
    unsigned char h7[] = {0xd3, 0xff, 0x12, 0x34, 0x56, 0x78};
    unsigned char h8[] = {0xfc, 0xe1};
        
    tdata test_item[] = {
        { h0, sizeof(h0), GPG_TAG_PKESK, 0 },
        { h1, sizeof(h1), GPG_TAG_SIGNATURE, 1 },
        { h2, sizeof(h2), GPG_TAG_SKESK, 0x1234 },
        { h3, sizeof(h3), GPG_TAG_ONE_PASS_SIGNATURE, 0xfedcba98 },
        { h4, sizeof(h4), GPG_TAG_SECRET_KEY, -1 },
        { h5, sizeof(h5), GPG_TAG_USER_ATTRIBUTE, 0x23 },
        { h6, sizeof(h6), GPG_TAG_SEIP_DATA, 0x1e3 },
        { h7, sizeof(h7), GPG_TAG_MOD_DETECT_CODE, 0x12345678 },
        { h8, sizeof(h8), GPG_TAG_RESERVED1, 2 },
    };

    for (size_t i = 0; i < (sizeof(test_item) / sizeof(tdata) - 1); i++) {
        //  Need to test the "partial length" extract separately, because we don't generate those headers yet
        do_tag_and_size(test_item + i);
    }
    int retval;
    gpg_tag tag;
    ssize_t size;

    retval = extract_gpg_tag_and_size(h8, &tag, &size);
    ASSERT_INT_EQ(retval, sizeof(h8));
    ASSERT_INT_EQ(tag, GPG_TAG_RESERVED1);
    ASSERT_INT_EQ(size, 2);

    //  Now try writing a file and testing the functions that read tag and size from the file.
    FILE * tstfile = tmpfile();
    for (size_t i = 0; i < (sizeof(test_item) / sizeof(tdata)); i++) {
        fwrite(test_item[i].h, 1, test_item[i].h_len, tstfile);
    }
    rewind(tstfile);
    
    for (size_t i = 0; i < (sizeof(test_item) / sizeof(tdata)); i++) {
        do_read_tag_and_size(tstfile, test_item + i);
    }

    retval = get_gpg_tag_and_size(tstfile, &tag, &size);    //  Should be at EOF now
    ASSERT_INT_EQ(retval, -1);

    TEST_DONE();
}

/*  Retrieve next packet - read header, then read body specified by header length.  */
static int
get_gpg_packet(FILE * infile, gpg_packet * pkt)
{
    int retval = -1;

    if (get_gpg_tag_and_size(infile, &pkt->tag, &pkt->len) == 0) {
        if (pkt->len > 0) {
            unsigned char * buf = malloc(pkt->len);
            int num_read = fread(buf, sizeof(unsigned char), pkt->len, infile);
            if (num_read == pkt->len) {
                pkt->data = sshbuf_from(buf, pkt->len);
                retval = 0;
            }
        }
    }

    return retval;
}

static void
do_put_pkt(FILE * tstfile, tdata * test_item)
{
    gpg_packet pkt;
    pkt.tag = test_item->tag;
    pkt.len = test_item->size;
    pkt.data = sshbuf_from(test_item->h, test_item->h_len);
    int retval = put_gpg_packet(tstfile, &pkt);
    ASSERT_INT_EQ(retval, 0);
}

static void
do_get_pkt(FILE * tstfile, tdata * test_item)
{
    gpg_packet pkt;
    int retval = get_gpg_packet(tstfile, &pkt);
    ASSERT_INT_EQ(retval, 0);
    ASSERT_INT_EQ(pkt.tag, test_item->tag);
    ASSERT_INT_EQ(pkt.len, test_item->size);
    ASSERT_INT_EQ(pkt.len, test_item->size);
    ASSERT_INT_EQ(memcmp(sshbuf_ptr(pkt.data), test_item->h, test_item->h_len), 0);
    sshbuf_free(pkt.data);
}

void
test_packets(void)
{
    TEST_START("get_and_put_packets");

    //  Some faux GPG messages
    unsigned char buf[] = {
        0x84, 0x04, 0x01, 0x23, 0x45, 0x67,
        0xd1, 0x04, 0x01, 0x23, 0x45, 0x67
    };

    unsigned char h0[] = {0x01, 0x23, 0x45, 0x67};
    unsigned char * h1 = malloc(256);
    for (int i = 0; i < 256; i++) {
        h1[i] = i;
    }
    unsigned char * h2 = malloc(4096);
    for (int i = 0; i < 4096; i++) {
        h2[i] = i;
    }
        
    tdata test_item[] = {
        { h0, sizeof(h0), GPG_TAG_PKESK, sizeof(h0) },          // Hand written from buf
        { h0, sizeof(h0), GPG_TAG_USER_ATTRIBUTE, sizeof(h0) }, // Hand written from buf
        { h0, sizeof(h0), GPG_TAG_PKESK, sizeof(h0) },
        { h1, 256, GPG_TAG_PKESK, 256 },
        { h2, 4096, GPG_TAG_PKESK, 4096 },
        { h0, sizeof(h0), GPG_TAG_USER_ATTRIBUTE, sizeof(h0) },
        { h1, 256, GPG_TAG_USER_ATTRIBUTE, 256 },
        { h2, 4096, GPG_TAG_USER_ATTRIBUTE, 4096 }
    };

    FILE * tstfile = tmpfile();
    fwrite(buf, 1, sizeof(buf), tstfile);
    for (size_t i = 2; i < sizeof(test_item) / sizeof(tdata); i++) {
        do_put_pkt(tstfile, test_item + i);
    }
    rewind(tstfile);

    for (size_t i = 0; i < sizeof(test_item) / sizeof(tdata); i++) {
        do_get_pkt(tstfile, test_item + i);
    }


    fclose(tstfile);
    gpg_packet pkt;
    int retval = put_gpg_packet(tstfile, &pkt);
    ASSERT_INT_EQ(retval, -1);

    //  Need to start over with a new empty file because Linux doesn't return an error on fread() of a
    //  closed file. It happily makes up some random crap. fwrite() on an empty file does seem to return
    //  an error, though
    tstfile = tmpfile();
    retval = get_gpg_packet(tstfile, &pkt);
    ASSERT_INT_EQ(retval, -1);
    fclose(tstfile);

    TEST_DONE();
}
