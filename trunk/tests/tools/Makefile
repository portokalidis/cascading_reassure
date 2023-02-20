CXX=g++

EXTRA_FLAGS=-Wall -Werror -O3

include ../../makefile.pin
PIN_CXXFLAGS+=$(EXTRA_FLAGS)

TOOLS=ret_overwrite_tool.so version.so invalidate.so versionseq.so fork.so
TOOLS+=find_routines.so memwrite_collect.so


all: $(TOOLS)

.PHONY: clean


$(TOOLS): %.so: %.o
	$(CXX) $(PIN_LDFLAGS) -o $@ $< $(PIN_LIBS)

%.o: %.cpp
	$(CXX) $(PIN_CXXFLAGS) -c $^

clean:
	rm -f *.o $(TOOLS)
