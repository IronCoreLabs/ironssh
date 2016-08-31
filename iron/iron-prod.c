#include    <sys/types.h>
#include    <pwd.h>

struct passwd *
iron_get_current_user(uid_t uid)
{
    return getpwuid(uid);
}
