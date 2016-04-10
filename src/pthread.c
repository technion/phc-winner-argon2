#include <pthread.h>
int   pthread_create(pthread_t *a, const pthread_attr_t *b,
                  void *(*)(void *c), void *d) {
    return 0;
}

void  pthread_exit(void *) {
    return;
}
int   pthread_join(pthread_t a, void **b) {
    return 0;
}
