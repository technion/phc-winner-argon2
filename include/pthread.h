#ifndef TIS_THREADS
#define TIS_THREADS
typedef int pthread_t;
typedef int pthread_attr_t;
int   pthread_create(pthread_t *, const pthread_attr_t *,
                  void *(*)(void *), void *);
void  pthread_exit(void *);
int   pthread_join(pthread_t, void **);
#endif
#include <stdio.h>
