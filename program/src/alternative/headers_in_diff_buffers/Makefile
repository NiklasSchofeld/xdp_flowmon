# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := ./
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= $(abspath ../../tools/bpftool)
LIBBPF_SRC := $(abspath ../../libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
VMLINUX := ../../vmlinux/vmlinux.h

# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(OUTPUT) -I../../libbpf/include/uapi -I$(dir $(VMLINUX))
CFLAGS := -g -Wall -O2
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

#program/app name here:
APPS = bpflowmon

USER_TARGETS := bpflowmon

USER_C := ${USER_TARGETS:=.c} flow_mgmt.c to_json.c
USER_OBJ := ${USER_C:.c=.o}


# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS) $(USER_OBJ)

$(OUTPUT) $(OUTPUT)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
#	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@






# Dependencies
USER_DEP := *.h
COMMON_H := bpflowmon.h
EXTRA_DEPS += *.h

$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h
#$(patsubst %,$(OUTPUT)/%,$(USER_OBJ)): %.o:

$(USER_OBJ): %.o: %.c $(COMMON_H) $(EXTRA_DEPS) $(USER_DEP) | $(OUTPUT)
# 	$(CC) -Wall -c -o $@ $<
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(APPS): %: $(OUTPUT)%.o $(USER_OBJ) $(LIBBPF_OBJ) | $(OUTPUT)
# 			$(CC) -Wall $(LDFLAGS) -o $@ \
#      		$(USER_OBJ) $(LIBS)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ -lelf -lz -o $@

#######################################################################################
# Build user-space code
# $(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

# $(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
# 	$(call msg,CC,$@)
# 	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# # Build application binary
# $(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(OUTPUT)
# 	$(call msg,BINARY,$@)
# 	$(Q)$(CC) $(CFLAGS) $^ -lelf -lz -o $@
########################################################################################

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:

