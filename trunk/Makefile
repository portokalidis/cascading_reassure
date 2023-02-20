include config.mak
include makefile.pin

EXTRA_FLAGS=-Wall -Wextra -Wno-unused-parameter -Wno-unused-result -Werror
LIBS=-lrt

ifeq ($(DEBUG_BUILD), 1)
EXTRA_FLAGS+=-O0 -g -ggdb
LIBS+=-lefence
else
EXTRA_FLAGS+=-O3
endif

ifeq ($(SAFECOPY_RESTORE), 1)
EXTRA_FLAGS+=-DSAFECOPY_RESTORE
endif

TOOLS=reassure.so cprofile.so conftest.so 
REASSURE_OBJS=libreassure.o RescuePoint.o threadstate.o utils.o
REASSURE_OBJS+=watchdog.o writeslog.o fork.o filter.o
REASSURE_OBJS+=syscall.o syscall_desc.o
REASSURE_HEADS=RescuePoint.hpp threadstate.hpp utils.hpp fork.h
REASSURE_HEADS+=watchdog.hpp writeslog.h log.hpp libreassure.hpp debug.h 
REASSURE_HEADS+=filter.hpp cache.h
REASSURE_HEADS+=syscall_desc.h syscall.hpp
CONFTEST_OBJS=conftest.o RescuePoint.o utils.o

ifeq ($(CASCADING_RPS), 1)
EXTRA_FLAGS+=-DCASCADING_RPS
REASSURE_OBJS+=checkpoint_xchg.o
REASSURE_HEADS+=checkpoint_xchg.hpp
endif


PIN_CXXFLAGS+=$(EXTRA_FLAGS)
# Some distros define sem_post() in libpthread.so
PIN_LIBS+=-lpthread

VNAME=$(shell cat VERSION)


all: $(TOOLS)

.PHONY: clean dist tests

reassure.so: reassure.o libreassure.a
	$(CXX) $(PIN_LDFLAGS) -o $@ $^ $(PIN_LIBS) $(LIBS)

libreassure.a: $(REASSURE_OBJS)
	$(AR) $(ARFLAGS) $@ $^

conftest.so: $(CONFTEST_OBJS)
	$(CXX) $(PIN_LDFLAGS) -o $@ $^ $(PIN_LIBS)

cprofile.so: cprofile.o 
	$(CXX) $(PIN_LDFLAGS) -o $@ $^ $(PIN_LIBS)

%.o: %.cpp $(REASSURE_HEADS)
	$(CXX) $(PIN_CXXFLAGS) $(CXXFLAGS) -c $< 


tests:
	cd tests && make

dist:
	make clean
	mkdir -p /tmp/$(VNAME)
	find . | grep -v '/\.' | cpio -dump /tmp/$(VNAME)/
	cd /tmp && rm -f $(VNAME).tar.gz && \
		tar -c $(VNAME) | gzip > $(VNAME).tar.gz
	mv /tmp/$(VNAME).tar.gz .
	rm -rf /tmp/$(VNAME)


clean:
	cd tests && make clean
	rm -f *.o $(TOOLS) libreassure.a

