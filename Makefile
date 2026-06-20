#!/usr/bin/make -f

include common.mk
VERSION := $(MAJOR).$(MINOR).$(PATCH)
PREFIX ?= /usr/local
BUILD_DIR := build
RELEASE_OPTIMIZE_FLAGS ?= -O3
DEBUG_OPTIMIZE_FLAGS ?= -g -O0 -U_FORTIFY_SOURCE
AR = ar

SO := so
LIBCE_LDFLAGS := -Wl,-soname,libce.so.$(MAJOR) \
                   -Wl,--version-script,version_script.ver
LIBCE_LIBS := -lsodium

RELEASE_TARGET := $(BUILD_DIR)/libce.$(SO).$(VERSION)
STATIC_RELEASE_TARGET := $(BUILD_DIR)/libce.a
DEBUG_TARGET := $(BUILD_DIR)/libce_debug.$(SO).$(VERSION)

PUBLIC_HEADERS := include/libce/olm.h include/libce/outbound_group_session.h include/libce/inbound_group_session.h include/libce/pk.h include/libce/sas.h include/libce/error.h include/libce/olm_export.h

SOURCES := $(wildcard src/*.c) \
    lib/crypto-algorithms/sha256.c \
    lib/crypto-algorithms/aes.c \
    lib/curve25519-donna/curve25519-donna.c

TEST_SOURCES := $(wildcard tests/test_*.c)

OBJECTS := $(patsubst %.c,%.o,$(SOURCES))
RELEASE_OBJECTS := $(addprefix $(BUILD_DIR)/release/,$(OBJECTS))
DEBUG_OBJECTS := $(addprefix $(BUILD_DIR)/debug/,$(OBJECTS))
TEST_BINARIES := $(patsubst tests/%,$(BUILD_DIR)/tests/%,$(basename $(TEST_SOURCES)))

DOCS := tracing/README.html \
    docs/megolm.html \
    docs/olm.html \
    docs/signing.html \
    README.html \
    CHANGELOG.html

CPPFLAGS += -Iinclude -Ilib \
    -DLIBCE_VERSION_MAJOR=$(MAJOR) -DLIBCE_VERSION_MINOR=$(MINOR) \
    -DLIBCE_VERSION_PATCH=$(PATCH)

# we rely on <stdint.h>, which was introduced in C99
CFLAGS += -Wall -std=c99
LDFLAGS += -Wall
LDLIBS += $(LIBCE_LIBS)

CFLAGS_NATIVE = -fPIC

# generate .d files when compiling
CPPFLAGS += -MMD

### per-target variables

$(RELEASE_OBJECTS): CFLAGS += $(RELEASE_OPTIMIZE_FLAGS) $(CFLAGS_NATIVE)
$(RELEASE_TARGET): LDFLAGS += $(RELEASE_OPTIMIZE_FLAGS)

$(DEBUG_OBJECTS): CFLAGS += $(DEBUG_OPTIMIZE_FLAGS) $(CFLAGS_NATIVE)
$(DEBUG_TARGET): LDFLAGS += $(DEBUG_OPTIMIZE_FLAGS)

$(TEST_BINARIES): CPPFLAGS += -Itests/include
$(TEST_BINARIES): LDFLAGS += $(DEBUG_OPTIMIZE_FLAGS) -L$(BUILD_DIR)
$(TEST_BINARIES): LDLIBS += -lcmocka

mkdir = mkdir -p $(1)

### top-level targets

lib: $(RELEASE_TARGET)
.PHONY: lib

$(RELEASE_TARGET): $(RELEASE_OBJECTS)
	@echo
	@echo '****************************************************************************'
	@echo '* WARNING: Building libce with make is deprecated. Please use CMake instead. *'
	@echo '****************************************************************************'
	@echo

	$(CXX) $(LDFLAGS) --shared -fPIC \
	    $(LIBCE_LDFLAGS) \
	    $(OUTPUT_OPTION) $(RELEASE_OBJECTS) $(LIBCE_LIBS)
	ln -sf libce.$(SO).$(VERSION) $(BUILD_DIR)/libce.$(SO).$(MAJOR)
	ln -sf libce.$(SO).$(VERSION) $(BUILD_DIR)/libce.$(SO)

debug: $(DEBUG_TARGET)
.PHONY: debug

$(DEBUG_TARGET): $(DEBUG_OBJECTS)
	$(CXX) $(LDFLAGS) --shared -fPIC \
	    $(LIBCE_LDFLAGS) \
	    $(OUTPUT_OPTION) $(DEBUG_OBJECTS) $(LIBCE_LIBS)
	ln -sf libce_debug.$(SO).$(VERSION) $(BUILD_DIR)/libce_debug.$(SO).$(MAJOR)

static: $(STATIC_RELEASE_TARGET)
.PHONY: static

$(STATIC_RELEASE_TARGET): $(RELEASE_OBJECTS)
	$(AR) rcs $@ $^

build_tests: $(TEST_BINARIES)

test: build_tests
	for i in $(TEST_BINARIES); do \
	    echo $$i; \
	    $$i || exit $$?; \
	done

test_mem: build_tests
	for i in $(TEST_BINARIES); do \
	    echo $$i; \
	    valgrind -q --leak-check=yes --exit-on-first-error=yes --error-exitcode=1 $$i || exit $$?; \
	done

all: test lib debug doc
.PHONY: all

install-headers: $(PUBLIC_HEADERS)
	test -d $(DESTDIR)$(PREFIX)/include/libce || $(call mkdir,$(DESTDIR)$(PREFIX)/include/libce)
	install $(PUBLIC_HEADERS) $(DESTDIR)$(PREFIX)/include/libce/
.PHONY: install-headers

install-debug: debug install-headers
	test -d $(DESTDIR)$(PREFIX)/lib || $(call mkdir,$(DESTDIR)$(PREFIX)/lib)
	install $(DEBUG_TARGET) $(DESTDIR)$(PREFIX)/lib/libce_debug.$(SO).$(VERSION)
	ln -sf libce_debug.$(SO).$(VERSION) $(DESTDIR)$(PREFIX)/lib/libce_debug.$(SO).$(MAJOR)
	ln -sf libce_debug.$(SO).$(VERSION) $(DESTDIR)$(PREFIX)/lib/libce_debug.$(SO)
.PHONY: install-debug

install: lib install-headers
	test -d $(DESTDIR)$(PREFIX)/lib || $(call mkdir,$(DESTDIR)$(PREFIX)/lib)
	install $(RELEASE_TARGET) $(DESTDIR)$(PREFIX)/lib/libce.$(SO).$(VERSION)
	ln -sf libce.$(SO).$(VERSION) $(DESTDIR)$(PREFIX)/lib/libce.$(SO).$(MAJOR)
	ln -sf libce.$(SO).$(VERSION) $(DESTDIR)$(PREFIX)/lib/libce.$(SO)
.PHONY: install

clean:;
	rm -rf $(BUILD_DIR) $(DOCS)
.PHONY: clean

doc: $(DOCS)
.PHONY: doc

### rules for building objects
$(BUILD_DIR)/release/%.o: %.c
	$(call mkdir,$(dir $@))
	$(COMPILE.c) $(OUTPUT_OPTION) $<

$(BUILD_DIR)/debug/%.o: %.c
	$(call mkdir,$(dir $@))
	$(COMPILE.c) $(OUTPUT_OPTION) $<

$(BUILD_DIR)/tests/%: tests/%.c $(DEBUG_OBJECTS)
	$(call mkdir,$(dir $@))
	$(LINK.c) -o $@ $< $(DEBUG_OBJECTS) $(LOADLIBES) $(LDLIBS)

%.html: %.rst
	rst2html $< $@

%.html: %.md
	pandoc --from markdown --to html5 --standalone --lua-filter gitlab-math.lua --katex -o $@ $<

### dependencies

-include $(RELEASE_OBJECTS:.o=.d)
-include $(DEBUG_OBJECTS:.o=.d)
-include $(TEST_BINARIES:=.d)
