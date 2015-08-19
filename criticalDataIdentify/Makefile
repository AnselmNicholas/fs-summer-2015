LIBTRACE_DIR = /share/skiplib/bap/libtracewrap/libtrace
PIN_DIR = /share/skiplib/bap/pin
BIN_DIR = bin
CXX = g++
CXXFLAGS = -I$(LIBTRACE_DIR)/src/cpp/pb  -I$(LIBTRACE_DIR)/src/common \
	 -I$(LIBTRACE_DIR)/protobuf/src -I$(LIBTRACE_DIR)/src/cpp \
	-Wall -g

LBITS := $(shell getconf LONG_BIT)

ifeq ($(LBITS), 32)
PINARCH = ia32
else
PINARCH = intel64
endif

LDLIBS = $(LIBTRACE_DIR)/src/cpp/libtrace.a $(LIBTRACE_DIR)/protobuf/src/.libs/libprotobuf.a -lpthread
PINFLAGS = -Wl,--hash-style=sysv -L $(PIN_DIR)/extras/xed2-$(PINARCH)/lib/ -lxed -I $(PIN_DIR)/extras/xed2-$(PINARCH)/include/

.PHONY: all clean

all:  $(BIN_DIR)/fetchCallFromTrace $(BIN_DIR)/fetchParam
	
$(BIN_DIR)/fetchCallFromTrace: fetchCallsFromTrace.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

$(BIN_DIR)/fetchParam: fetchParam.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS) $(PINFLAGS) -DHHPIN32

clean:
	-rm -f $(BIN_DIR)/fetchCallFromTrace $(BIN_DIR)/fetchParam
