#ifndef __dummy_h__
#define __dummy_h__

#include "heim.h"

#include <Heimdal/krb5_err.h>
#include <errno.h>
#include <stdlib.h>

#define dummy(func_name, ret_type, args, retval)                        \
    ret_type func_name args                                                  \
    {                                                                   \
        mshim_log_function_missing( #func_name );                       \
        return (retval);                                                \
    }

#define dummyk5(func_name, ret_type, args, retval)                      \
    ret_type KRB5_CALLCONV mit_ ## func_name args                       \
    {                                                                   \
        mshim_log_function_missing( #func_name );                       \
        return (retval);                                                \
    }

#define dummyk5v(func_name, args)                                       \
    void KRB5_CALLCONV mit_ ## func_name args                           \
    {                                                                   \
        mshim_log_function_missing( #func_name );                       \
        return;                                                         \
    }

#define quietdummy(func_name, ret_type, args, retval)   \
    ret_type func_name args                                  \
    {                                                   \
        return (retval);                                \
    }

#define quietdummyk5(func_name, ret_type, args, retval)   \
    ret_type KRB5_CALLCONV mit_ ## func_name args              \
    {                                                     \
        return (retval);                                  \
    }

#endif  /* __dummy_h__ */
