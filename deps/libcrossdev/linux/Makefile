include ../makefile.pin.unix
include ../makefile.common

CXXFLAGS+=$(PIN_CXXFLAGS) $(PIN_INCLUDES)

TARGET_OBJS=libcrossdev.o
TARGET_HEADERS=libcrossdev.hpp ../libcrossdev.hpp


all: $(TARGET_OBJS)

.PHONY: clean


$(TARGET_OBJS): %.o: %.cpp $(TARGET_HEADERS) 
	$(CXX) $(CXXFLAGS) $(COMP_OBJ)$@ $<


clean:
	rm -f *.o
