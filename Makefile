# Makefile for irssi-fe-web module

include config.mk

# Paths
SRCDIR = src
MODULE_SO = lib$(MODULE_NAME).so
MODULE_DIR = $(PREFIX)/modules

# Source files
SOURCES = $(SRCDIR)/fe-web.c \
          $(SRCDIR)/fe-web-client.c \
          $(SRCDIR)/fe-web-server.c \
          $(SRCDIR)/fe-web-signals.c \
          $(SRCDIR)/fe-web-websocket.c \
          $(SRCDIR)/fe-web-ssl.c \
          $(SRCDIR)/fe-web-crypto.c \
          $(SRCDIR)/fe-web-json.c \
          $(SRCDIR)/fe-web-netserver.c \
          $(SRCDIR)/fe-web-utils.c

OBJECTS = $(SOURCES:.c=.o)

# Auto-detect irssi headers
ifeq ($(wildcard $(IRSSI_INCLUDE)/src/common.h),)
    IRSSI_INCLUDE := $(shell \
        for dir in /usr/include/irssi /usr/local/include/irssi \
                   /opt/homebrew/include/irssi /opt/local/include/irssi; do \
            test -f $$dir/src/common.h && echo $$dir && break; \
        done)
endif

ifeq ($(wildcard $(IRSSI_INCLUDE)/src/common.h),)
    $(error Cannot find irssi headers. Set IRSSI_INCLUDE=/path/to/irssi/include)
endif

# Compiler flags
CFLAGS += -fPIC -Wall -Wextra -std=gnu99
CFLAGS += -I$(IRSSI_INCLUDE)
CFLAGS += $(shell $(PKG_CONFIG) --cflags glib-2.0 openssl)

# Linker flags
LDFLAGS += -shared
LIBS += $(shell $(PKG_CONFIG) --libs glib-2.0 openssl)

# Build info
$(info Building $(MODULE_NAME) from $(SRCDIR)/)
$(info irssi headers: $(IRSSI_INCLUDE))

.PHONY: all clean install uninstall help

all: $(MODULE_SO)

$(MODULE_SO): $(OBJECTS)
	@echo "Linking $@..."
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
	@echo "Build successful: $@"

%.o: %.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c -o $@ $<

install: $(MODULE_SO)
	@echo "Installing to $(MODULE_DIR)..."
	@mkdir -p $(MODULE_DIR)
	install -m 644 $(MODULE_SO) $(MODULE_DIR)/
	@echo "Installed: $(MODULE_DIR)/$(MODULE_SO)"
	@echo ""
	@echo "To load in irssi: /LOAD $(MODULE_NAME)"

uninstall:
	rm -f $(MODULE_DIR)/$(MODULE_SO)
	@echo "Uninstalled"

clean:
	rm -f $(OBJECTS) $(MODULE_SO)
	@echo "Cleaned"

help:
	@echo "Targets:"
	@echo "  make          - Build module"
	@echo "  make install  - Install to ~/.irssi/modules"
	@echo "  make clean    - Remove build artifacts"
	@echo ""
	@echo "Configuration (config.mk):"
	@echo "  IRSSI_INCLUDE - Path to irssi headers"
	@echo "  PREFIX        - Installation prefix"
