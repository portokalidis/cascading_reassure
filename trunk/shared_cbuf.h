#ifndef SHARED_CBUF_H
#define SHARED_CBUF_H

#include <semaphore.h>

/**
 * Circular buffer structure
 */
struct shared_cbuf {
	unsigned char *rdptr, *wrptr, *buf;
	size_t avail, len;
};


bool shared_cbuf_init(struct shared_cbuf *sc, size_t len);

void shared_cbuf_cleanup(struct shared_cbuf *sc);


#endif
