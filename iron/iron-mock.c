#include    <sys/types.h>
#include    <pwd.h>
#include    <stdio.h>
#include    <stdlib.h>

#include    "xmalloc.h"

//  Alternative to the system getpwuid function that will return a test directory
struct passwd *
iron_get_current_user(uid_t uid)
{
    printf("\n***Called local getpwuid***\n\n");
    static struct passwd local_pwd;
    static int test_inited = 0;

    if (!test_inited) {
        local_pwd.pw_name = xstrdup(getenv("IRON_TEST_USER"));
        local_pwd.pw_dir  = xstrdup(getenv("IRON_TEST_DIR"));
        test_inited = 1;
    }

    return &local_pwd;
    
}
