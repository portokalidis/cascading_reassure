include makefile.config
include makefile.pin.unix

CXXFLAGS=-Wall -Wextra -Wno-unused-parameter -Wno-unused-result -Werror

ifeq ($(DEBUG_BUILD), 1)
CXXFLAGS+=-O0 -g -ggdb
LIBS+=-lefence
else
CXXFLAGS+=-O3
endif

CXXFLAGS+=$(PIN_CXXFLAGS) $(PIN_INCLUDES)

TARGET=libminestrone.a
LIBMINESTRONE_OBJS=watchdog.o notify.o
LIBMINESTRONE_HEADS=libminestrone.hpp minestrone_opts.hpp watchdog_opts.hpp


all: $(TARGET)

.PHONY: clean


$(TARGET): $(LIBMINESTRONE_OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(LIBMINESTRONE_OBJS): %.o: %.cpp $(LIBMINESTRONE_HEADS) 
	$(CXX) $(CXXFLAGS) -c $< 


VNAME=$(shell cat VERSION)

dist:
	make clean
	mkdir -p /tmp/$(VNAME)
	find . | grep -v '/\.' | cpio -dump /tmp/$(VNAME)/
	cd /tmp && rm -f $(VNAME).tar.gz && \
		tar -c $(VNAME) | gzip > $(VNAME).tar.gz
	mv /tmp/$(VNAME).tar.gz .
	rm -rf /tmp/$(VNAME)

clean:
	rm -f $(TARGET) *.o

