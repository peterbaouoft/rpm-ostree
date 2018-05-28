#include "config.h"
#include "libglnx.h"
#include "rpmostree-util.h"
#include "rpmostree-json-parsing.h"
#include "rpmostree-passwd-util.h"

static const gchar *test_passwd[] = {
  "chrony:x:994:992::/var/lib/chrony:/sbin/nologin",
  "tcpdump:x:72:72::/:/sbin/nologin",
  "systemd-timesync:x:993:991:systemd Time Synchronization:/:/sbin/nologin",
  "cockpit-ws:x:988:987:User for cockpit-ws:/:/sbin/nologin",
  NULL
};

static const gchar *expected_sysuser_passwd_content[] ={
  "u chrony 994:992 - /var/lib/chrony",
  "u tcpdump 72 - /",
  "u systemd-timesync 993:991 'systemd Time Synchronization' /",
  "u cockpit-ws 988:987 'User for cockpit-ws' /",
  NULL
};

/* Create a variant for mapping name --> sysuser string content */
static GVariantDict
get_sysuser_content_variant (const char **content)
{
  GVariantDict dict;
  g_variant_dict_init (&dict, NULL);
  for (char **iter = (char **)content; iter && *iter; iter++)
  {
    const char *sysuser_ent_content = *iter;
    g_auto(GStrv) entry_list = g_strsplit(sysuser_ent_content, " ", -1);
    char *sysuser_name = entry_list[1];
    g_variant_dict_insert(&dict, sysuser_name, "^as", entry_list);
  }

  return dict;
}

static void
test_passwd_conversion(void)
{
  gboolean ret;
  g_autoptr(GHashTable) sysusers_table = NULL;
  g_autoptr(GError) error = NULL;

  /* Check validity of the sysusers conversion */
  g_autofree char* test_content = g_strjoinv ("\n", (char **)test_passwd);
  g_autoptr(GPtrArray) passwd_ents = rpmostree_passwd_data2passwdents (test_content);
  ret = rpmostree_passwdents2sysusers (passwd_ents, &sysusers_table, &error);
  g_assert (ret);
  g_assert_no_error (error);

  /* Check Hashtable properties */
  g_assert (sysusers_table);
  g_assert_cmpuint (4, ==, g_hash_table_size (sysusers_table));

  /* Check Hashtable content */
  g_auto(GVariantDict) sysuser_dict =  get_sysuser_content_variant (expected_sysuser_passwd_content);
  GLNX_HASH_TABLE_FOREACH_KV (sysusers_table, const char*,  key, struct sysuser_ent*, sysuser_ent)
    {
      g_assert (g_str_equal (key, sysuser_ent->name));
      g_autofree const char *const * sysent_list = NULL;
      g_variant_dict_lookup (&sysuser_dict, key, "^a&s", &sysent_list);
      g_assert (g_str_equal (sysuser_ent->type, (char **)sysent_list[0]));
      g_assert (g_str_equal (sysuser_ent->name, (char **)sysent_list[1]));
      g_assert (g_str_equal (sysuser_ent->id, (char **)sysent_list[2]));\
    }

}

int
main (int argc,
      char *argv[])
{
  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/sysusers/passwd_conversion", test_passwd_conversion);
  return g_test_run ();
}

