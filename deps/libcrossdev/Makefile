ifeq ($(OS),Windows_NT)
	include makefile.pin.windows
	LIBCROSSDEV_OBJS=windows/libcrossdev.o
	LIBCROSSDEV_HEADS=windows/libcrossdev.hpp
	SUBDIR=windows
else
	include makefile.pin.unix
	LIBCROSSDEV_OBJS=linux/libcrossdev.o
	LIBCROSSDEV_HEADS=linux/libcrossdev.hpp
	SUBDIR=linux
endif
include makefile.common

CXXFLAGS+=$(PIN_CXXFLAGS) $(PIN_INCLUDES)

TARGET=libcrossdev.$(LIBEXT)
LIBCROSSDEV_OBJS+=libcrossdev.o
LIBCROSSDEV_HEADS+=libcrossdev.hpp


all: $(TARGET)

.PHONY: clean dist $(SUBDIR)


$(TARGET): $(LIBCROSSDEV_OBJS) $(SUBDIR)
	$(SLINK) $(SLINK_OUT)$@ $(LIBCROSSDEV_OBJS)

windows:
	cd windows && make DEBUG=$DEBUG

linux:
	cd linux && make DEBUG=$DEBUG

$(LIBCROSSDEV_OBJS): %.o: %.cpp $(LIBCROSSDEV_HEADS) 
	$(CXX) $(CXXFLAGS) $(COMP_OBJ)$@ $<

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
	rm -f libcrossdev.lib libcrossdev.a *.o *.pdb

