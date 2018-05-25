#include "config.h"
#include "libglnx.h"
#include "sysusers.h"


static const gchar *test_passwd[] = {
  "chrony:x:994:992::/var/lib/chrony:/sbin/nologin",
  "tcpdump:x:72:72::/:/sbin/nologin",
  "systemd-timesync:x:993:991:systemd Time Synchronization:/:/sbin/nologin",
  "cockpit-ws:x:988:987:User for cockpit-ws:/:/sbin/nologin"
}

static void
test_passwd_conversion(void)
{
  g_autoptr(GPtrArray) passwd_ents = rpmostree_passwd_data2passwdents (test_passwd)
  g_auto
  if (!rpmostree_passwdents2sysusers(passwd_ents, 
}

