#include "config.h"
#include "libglnx.h" 
#include "rpmostree-util.h"
#include "rpmostree-json-parsing.h"
#include "rpmostree-passwd-util.h"
#include "rpmostree-builtins.h"

static char *opt_conversion_location;


static GOptionEntry conversion_option_entries[] = {
  { "conversion_dir", 0, 0, G_OPTION_ARG_STRING, &opt_conversion_location, "Directory to convert", "CONVERSION_DIR"},
  { NULL }
};

// Temporarily take one argument --> mainly to convert the entries from /usr/lib/passwd into
// entries into sysusers.d 
gboolean rpmostree_builtin_temp_convert (int         argc, 
                                         char      **argv,
                                         RpmOstreeCommandInvocation *invocation,
                                         GCancellable  *cancellable,
                                         GError       **error)
{
  g_autoptr(GOptionContext) context = g_option_context_new ("");
  if (!rpmostree_option_context_parse (context,
                                       conversion_option_entries,
                                       &argc, &argv,
                                       invocation,
                                       cancellable,
                                       NULL, NULL, NULL, NULL, NULL, error))
    return FALSE;
  g_print("Hi, this is a test\n"); 
  /* Test the output for conversion, right now we can already convert the content into one string conten. The next step would just be to write a function to write sysusers entries to a new place */
 

  // Now we open the /usr/lib/passwd directory and change its stream to convert? Yea...

  const char* passwd_content = glnx_file_get_contents_utf8_at (AT_FDCWD, "/usr/lib/passwd", NULL, cancellable, error);
  const char* group_content = glnx_file_get_contents_utf8_at (AT_FDCWD, "/usr/lib/group", NULL, cancellable, error);

  g_print ("%s\n", passwd_content);
  g_print ("%s\n", group_content);
  // g_autoptr(GPtrArray) converted_ents =  
  g_autoptr(GPtrArray) passwd_ents = rpmostree_passwd_data2passwdents (passwd_content);
  g_autoptr(GPtrArray) group_ents = rpmostree_passwd_data2groupents (group_content);
  g_autoptr(GHashTable) sysusers_table = NULL;
  rpmostree_passwdents2sysusers (passwd_ents, &sysusers_table, error);
  rpmostree_groupents2sysusers (group_ents, &sysusers_table, error); 

  g_autofree char* sysuser_converted_content = NULL;
  rpmostree_passwd_sysusers2char (sysusers_table, &sysuser_converted_content, error);
  
  g_print("%s", sysuser_converted_content);
  
  //g_file_set_contents (
  return TRUE;
}
