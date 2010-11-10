
#include <ws2tcpip.h>
#include <windows.h>

#ifndef EINVAL
#define EINVAL          22
#endif

typedef HANDLE pthread_mutex_t;

typedef struct pthread_mutexattr {
    int dummy;
} pthread_mutexattr_t;

#define PTHREAD_MUTEX_INITIALIZER NULL

__inline int
pthread_mutex_init(pthread_mutex_t * mutex,
                   const pthread_mutexattr_t * attr)
{
    (void) attr;
    *mutex = CreateMutex(NULL, FALSE, NULL);
    return (*mutex != NULL)? 0 : EINVAL;
}

__inline int
pthread_mutex_lock(pthread_mutex_t * mutex)
{
    DWORD result;

    result = WaitForSingleObject(*mutex, INFINITE);

    return (result == WAIT_OBJECT_0)? 0 : EINVAL;
}

__inline int
pthread_mutex_unlock(pthread_mutex_t * mutex)
{
    return (ReleaseMutex(*mutex))? 0 : EINVAL;
}

__inline int
pthread_mutex_destroy(pthread_mutex_t * mutex)
{
    BOOL rv;

    rv = CloseHandle(*mutex);
    *mutex = NULL;
    return ((rv)? 0 : EINVAL);
}
