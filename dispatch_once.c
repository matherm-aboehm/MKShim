#include "dispatch_once.h"

#if _WIN32_WINNT >= 0x0600

struct worker_data {
    dispatch_once_func_t function;
    void                *context;
};

static BOOL CALLBACK
dispatch_worker(PINIT_ONCE ponce,
                PVOID param, PVOID *ctx)
{
    struct worker_data *d = (struct worker_data *) param;

    d->function(d->context);

    return TRUE;
}

void
dispatch_once_f(dispatch_once_t * predicate, void * context,
                dispatch_once_func_t function)
{
    struct worker_data d;

    d.function  = function;
    d.context   = context;

    InitOnceExecuteOnce(&predicate->once, dispatch_worker, &d, NULL);
}

#else

void
dispatch_once_f(dispatch_once_t * predicate, void * context,
                dispatch_once_func_t function)
{
    if (InterlockedIncrement(&predicate->initializing) == 1) {
        if (InterlockedIncrement(&predicate->initialized) == 1) {
            (*function)(context);
        } else {
            InterlockedDecrement(&predicate->initialized);
        }
        InterlockedDecrement(&predicate->initializing);
    } else {
        InterlockedDecrement(&predicate->initializing);
        do {
            Sleep(0);
        } while (predicate->initializing > 0);
    }
}

#endif
