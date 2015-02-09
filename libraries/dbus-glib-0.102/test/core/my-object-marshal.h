
#ifndef __my_object_marshal_MARSHAL_H__
#define __my_object_marshal_MARSHAL_H__

#include	<glib-object.h>

G_BEGIN_DECLS

/* NONE:STRING,INT,STRING (/home/smcv/src/fdo/dbus-glib/test/core/my-object-marshal.list:1) */
extern void my_object_marshal_VOID__STRING_INT_STRING (GClosure     *closure,
                                                       GValue       *return_value,
                                                       guint         n_param_values,
                                                       const GValue *param_values,
                                                       gpointer      invocation_hint,
                                                       gpointer      marshal_data);
#define my_object_marshal_NONE__STRING_INT_STRING	my_object_marshal_VOID__STRING_INT_STRING

/* NONE:STRING,BOXED (/home/smcv/src/fdo/dbus-glib/test/core/my-object-marshal.list:2) */
extern void my_object_marshal_VOID__STRING_BOXED (GClosure     *closure,
                                                  GValue       *return_value,
                                                  guint         n_param_values,
                                                  const GValue *param_values,
                                                  gpointer      invocation_hint,
                                                  gpointer      marshal_data);
#define my_object_marshal_NONE__STRING_BOXED	my_object_marshal_VOID__STRING_BOXED

G_END_DECLS

#endif /* __my_object_marshal_MARSHAL_H__ */

