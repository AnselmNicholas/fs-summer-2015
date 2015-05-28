LIBTRACE_DIR = libtrace
PIN_DIR = pin
BIN_DIR = bin
CXX = g++
CXXFLAGS = -I$(LIBTRACE_DIR)/src/cpp/pb  -I$(LIBTRACE_DIR)/src/common \
	 -I$(LIBTRACE_DIR)/protobuf/src -I$(LIBTRACE_DIR)/src/cpp \
	-Wall

LBITS := $(shell getconf LONG_BIT)

ifeq ($(LBITS), 32)
PINARCH = ia32
else
PINARCH = intel64
endif

LDLIBS = $(LIBTRACE_DIR)/src/cpp/libtrace.a $(LIBTRACE_DIR)/protobuf/src/.libs/libprotobuf.a -lpthread
PINFLAGS = -Wl,--hash-style=sysv -L $(PIN_DIR)/extras/xed2-$(PINARCH)/lib/ -lxed -I $(PIN_DIR)/extras/xed2-$(PINARCH)/include/

.PHONY: all clean

all:  $(BIN_DIR)/fetchCallFromTrace-32 $(BIN_DIR)/fetchCallFromTrace-64
	
$(BIN_DIR)/fetchCallFromTrace-32: fetchCallsFromTrace.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS) -DHHPIN32

$(BIN_DIR)/fetchCallFromTrace-64: fetchCallsFromTrace.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS) -DHHPIN64

clean:
	-rm -f $(BIN_DIR)/fetchCallFromTrace-32 $(BIN_DIR)/fetchCallFromTrace-64
