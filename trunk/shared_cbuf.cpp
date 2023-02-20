#include <sstream>
#include <iostream>

extern "C" {
#include <sys/mman.h>
}

#include "pin.H"
#include "log.hpp"
#include "debug.h"
#include "shared_cbuf.h"


bool shared_cbuf_init(struct shared_cbuf *sc, size_t len)
{
	// Allocate circular buffer
	sc->buf = (unsigned char *)mmap(NULL, len, PROT_READ|PROT_WRITE, 
			MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	if (sc->buf == MAP_FAILED)
		return false;
	
	sc->rdptr = sc->wrptr = sc->buf;
	sc->avail = 0;
	sc->len = len;
	return true;
}

void shared_cbuf_cleanup(struct shared_cbuf *sc)
{
	munmap(sc->buf, sc->len);
}
