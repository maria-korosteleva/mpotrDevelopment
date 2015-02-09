/* Integration tests for the dbus-daemon's uid-based hardening
 *
 * Author: Simon McVittie <simon.mcvittie@collabora.co.uk>
 * Copyright © 2010-2011 Nokia Corporation
 * Copyright © 2015 Collabora Ltd.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <config.h>

#include "test-utils-glib.h"

typedef struct {
    gboolean skip;

    TestMainContext *ctx;

    DBusError e;
    GError *ge;

    GPid daemon_pid;

    DBusConnection *conn;
} Fixture;

typedef struct {
    const char *config_file;
    TestUser user;
    gboolean expect_success;
} Config;

static void
setup (Fixture *f,
    gconstpointer context)
{
  const Config *config = context;
  gchar *address;

  f->ctx = test_main_context_get ();
  f->ge = NULL;
  dbus_error_init (&f->e);

  address = test_get_dbus_daemon (config ? config->config_file : NULL,
                                  TEST_USER_MESSAGEBUS,
                                  &f->daemon_pid);

  if (address == NULL)
    {
      f->skip = TRUE;
      return;
    }

  f->conn = test_connect_to_bus_as_user (f->ctx, address,
      config ? config->user : TEST_USER_ME);

  if (f->conn == NULL)
    f->skip = TRUE;

  g_free (address);
}

static void
test_uae (Fixture *f,
    gconstpointer context)
{
  const Config *config = context;
  DBusMessage *m;
  DBusPendingCall *pc;
  DBusMessageIter args_iter;
  DBusMessageIter arr_iter;

  if (f->skip)
    return;

  m = dbus_message_new_method_call (DBUS_SERVICE_DBUS,
      DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS, "UpdateActivationEnvironment");

  if (m == NULL)
    g_error ("OOM");

  dbus_message_iter_init_append (m, &args_iter);

  /* Append an empty a{ss} (string => string dictionary). */
  if (!dbus_message_iter_open_container (&args_iter, DBUS_TYPE_ARRAY,
        "{ss}", &arr_iter) ||
      !dbus_message_iter_close_container (&args_iter, &arr_iter))
    g_error ("OOM");

  if (!dbus_connection_send_with_reply (f->conn, m, &pc,
                                        DBUS_TIMEOUT_USE_DEFAULT) ||
      pc == NULL)
    g_error ("OOM");

  dbus_message_unref (m);
  m = NULL;

  if (dbus_pending_call_get_completed (pc))
    test_pending_call_store_reply (pc, &m);
  else if (!dbus_pending_call_set_notify (pc, test_pending_call_store_reply,
                                          &m, NULL))
    g_error ("OOM");

  while (m == NULL)
    test_main_context_iterate (f->ctx, TRUE);

  if (config->expect_success)
    {
      /* it succeeds */
      g_assert_cmpint (dbus_message_get_type (m), ==,
          DBUS_MESSAGE_TYPE_METHOD_RETURN);
    }
  else
    {
      /* it fails, yielding an error message with one string argument */
      g_assert_cmpint (dbus_message_get_type (m), ==, DBUS_MESSAGE_TYPE_ERROR);
      g_assert_cmpstr (dbus_message_get_error_name (m), ==,
          DBUS_ERROR_ACCESS_DENIED);
      g_assert_cmpstr (dbus_message_get_signature (m), ==, "s");
    }

  dbus_message_unref (m);
}

static void
teardown (Fixture *f,
    gconstpointer context G_GNUC_UNUSED)
{
  dbus_error_free (&f->e);
  g_clear_error (&f->ge);

  if (f->conn != NULL)
    {
      dbus_connection_close (f->conn);
      dbus_connection_unref (f->conn);
      f->conn = NULL;
    }

  if (f->daemon_pid != 0)
    {
      test_kill_pid (f->daemon_pid);
      g_spawn_close_pid (f->daemon_pid);
      f->daemon_pid = 0;
    }

  test_main_context_unref (f->ctx);
}

static Config root_ok_config = {
    "valid-config-files/multi-user.conf",
    TEST_USER_ROOT,
    TRUE
};

static Config messagebus_ok_config = {
    "valid-config-files/multi-user.conf",
    TEST_USER_MESSAGEBUS,
    TRUE
};

static Config other_fail_config = {
    "valid-config-files/multi-user.conf",
    TEST_USER_OTHER,
    FALSE
};

int
main (int argc,
    char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_bug_base ("https://bugs.freedesktop.org/show_bug.cgi?id=");

  g_test_add ("/uid-permissions/uae/root", Fixture, &root_ok_config,
      setup, test_uae, teardown);
  g_test_add ("/uid-permissions/uae/messagebus", Fixture, &messagebus_ok_config,
      setup, test_uae, teardown);
  g_test_add ("/uid-permissions/uae/other", Fixture, &other_fail_config,
      setup, test_uae, teardown);

  return g_test_run ();
}
