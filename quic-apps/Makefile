OS := $(shell uname)

CXXFLAGS = -std=c++17 -Wall -Werror -pedantic -fsanitize=address -g

INCLUDE_DIR = $(QUICHE_DIR)/include
INCS = -I. -I./quic -I$(INCLUDE_DIR)

LIB_DIR = $(QUICHE_DIR)/target/debug
BUILD_DIR = $(LIB_DIR)/build
LIBCRYPTO_DIR = $(dir $(shell find ${BUILD_DIR} -name libcrypto.a))
LIBSSL_DIR = $(dir $(shell find ${BUILD_DIR} -name libssl.a))
LDFLAGS = -L$(LIBCRYPTO_DIR) -L$(LIBSSL_DIR) -L$(LIB_DIR)

ifeq ($(OS), Darwin)
LDFLAGS += -framework Security
endif

LIBS = $(LIB_DIR)/libquiche.a -lev -ldl -pthread

all: main.cpp quic/quic_client.cpp quic/quic_common.cpp quic/quic_client.hpp quic/quic_common.hpp
	$(CXX) $(CXXFLAGS) $(INCS) $(LDFLAGS) main.cpp quic/quic_client.cpp quic/quic_common.cpp $(LIBS)

.PHONY: clean
clean:
	@$(RM) -rf a.out
