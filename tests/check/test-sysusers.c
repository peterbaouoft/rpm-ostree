#include "config.h"
#include "libglnx.h"
#include "rpmostree-util.h"
#include "rpmostree-json-parsing.h"
#include "rpmostree-passwd-util.h"

static const gchar *test_passwd[] = {
  "chrony:x:994:992::/var/lib/chrony:/sbin/nologin",
  "tcpdump:x:72:72::/:/sbin/nologin",
  "systemd-timesync:x:993:991:a:/:/sbin/nologin",
  "cockpit-ws:x:988:987:b:/:/sbin/nologin",
  NULL
};

static const gchar *expected_sysuser_passwd_content[] ={
  "u chrony 994:992 - /var/lib/chrony /sbin/nologin",
  "u tcpdump 72 - / /sbin/nologin",
  "u systemd-timesync 993:991 \"a\" / /sbin/nologin",
  "u cockpit-ws 988:987 \"b\" / /sbin/nologin",
  NULL
};

static const gchar *test_group[] = {
  "chrony:x:992:",
  "tcpdump:x:72:",
  "systemd-timesync:x:991:",
  "cockpit-ws:x:987:",
  "test:x:111:",
  NULL
};

static const gchar *expected_sysuser_group_content[] = {
  "g chrony 992 - - -",
  "g tcpdump 72 - - -",
  "g systemd-timesync 991 - - -",
  "g cockpit-ws 987 - - -",
  "g test 111 - - -",
  NULL
};

// ".*'([^']*)'.* ---> regex string"
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

static void setup_passwd_sysusers (GHashTable **out_table,
                                   GError     **error)
{
  /* Check validity of the sysusers conversion */
  g_autofree char* test_content = g_strjoinv ("\n", (char **)test_passwd);
  g_autoptr(GPtrArray) passwd_ents = rpmostree_passwd_data2passwdents (test_content);
  gboolean ret = rpmostree_passwdents2sysusers (passwd_ents, out_table, error);
  g_assert (ret);
  g_assert_no_error (*error);
}

static void setup_group_sysusers (GHashTable **out_table,
                                  GError     **error)
{
  /* Check if the conversion itself is valid */
  g_autofree char *test_content = g_strjoinv ("\n", (char **)test_group);
  g_autoptr(GPtrArray) group_ents = rpmostree_passwd_data2groupents (test_content);
  gboolean ret = rpmostree_groupents2sysusers (group_ents, out_table, error);
  g_assert (ret);
  g_assert_no_error (*error);
}

static void check_sysuser_content (const char       **expected_content,
                                   GHashTable       *sysusers_table)
{
  /* Check Hashtable content */
  g_auto(GVariantDict) sysuser_dict =  get_sysuser_content_variant (expected_content);
  GLNX_HASH_TABLE_FOREACH_KV (sysusers_table, const char*,  key, struct sysuser_ent*, sysuser_ent)
    {
      /* For gecos, and dir, we set the sysuser_ent to NULL when empty, so we convert
       * them back here */
      const char *shell = sysuser_ent->shell ?: "-";
      const char *gecos = sysuser_ent->gecos ?: "-";
      const char *dir = sysuser_ent->dir ?: "-";
      g_assert (g_str_equal (key, sysuser_ent->name));
      g_autofree const char *const * sysent_list = NULL;
      g_variant_dict_lookup (&sysuser_dict, key, "^a&s", &sysent_list);
      g_assert (g_str_equal (sysuser_ent->type, (char **)sysent_list[0]));
      g_assert (g_str_equal (sysuser_ent->name, (char **)sysent_list[1]));
      g_assert (g_str_equal (sysuser_ent->id, (char **)sysent_list[2]));
      g_assert (g_str_equal (shell, (char **)sysent_list[5]));
      g_assert (g_str_equal (gecos, (char **)sysent_list[3]));
      g_assert (g_str_equal (dir, (char **)sysent_list[4]));
    }
}

static void
test_passwd_conversion(void)
{
  g_autoptr(GHashTable) sysusers_table = NULL;
  g_autoptr(GError) error = NULL;

  setup_passwd_sysusers (&sysusers_table, &error);

  /* Check Hashtable properties */
  g_assert (sysusers_table);
  g_assert_cmpuint (4, ==, g_hash_table_size (sysusers_table));

  check_sysuser_content (expected_sysuser_passwd_content, sysusers_table);

}

static void
test_group_conversion(void)
{
  g_autoptr(GHashTable) sysusers_table = NULL;
  g_autoptr(GError) error = NULL;

  setup_group_sysusers (&sysusers_table, &error);

  /* Check validity of hashtable */
  g_assert (sysusers_table);
  g_assert_cmpuint (5, ==, g_hash_table_size (sysusers_table));

  check_sysuser_content (expected_sysuser_group_content, sysusers_table);
}

static void
test_sysuser_entry_collision(void)
{
  /* That will be the case when, we are trying to add a group entry
   * with the same name as hashtable's sysentry, and the stored gid matches */
  g_autoptr(GHashTable) sysusers_table = NULL;
  g_autoptr(GError) error = NULL;

  setup_passwd_sysusers (&sysusers_table, &error);
  setup_group_sysusers (&sysusers_table, &error);

  /* Check collision handle here */
  g_print("Test freeing hashtable\n");
  g_assert_cmpuint (5, ==, g_hash_table_size (sysusers_table));
}

static void
test_sysusers_conversion(void)
{
  g_autoptr(GHashTable) sysusers_table = NULL;
  g_autoptr(GError) error = NULL;

  setup_passwd_sysusers (&sysusers_table, &error);
  g_autofree gchar* converted_content = NULL;
  rpmostree_passwd_sysusers2char (sysusers_table, &converted_content, &error);
  g_print ("%s\n", converted_content);
}
int
main (int argc,
      char *argv[])
{
  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/sysusers/passwd_conversion", test_passwd_conversion);
  g_test_add_func ("/sysusers/group_conversion", test_group_conversion);
  g_test_add_func ("/sysusers/collision_check", test_sysuser_entry_collision);
  g_test_add_func ("/sysusers/conversion_test", test_sysusers_conversion);
  return g_test_run ();
}

