#pragma once

#include <windows.h>

typedef struct dispatch_once {

#if _WIN32_WINNT >= 0x0600

    INIT_ONCE   once;

#define DISPATCH_ONCE_INITIALIZER {{0}}

#else

    LONG        initialized;
    LONG        initializing;

#define DISPATCH_ONCE_INITIALIZER {0,0}

#endif

} dispatch_once_t;


typedef void (*dispatch_once_func_t)(void *);

void dispatch_once_f(dispatch_once_t * predicate, void * context,
                     dispatch_once_func_t function);
