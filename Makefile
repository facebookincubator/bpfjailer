# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# Standalone build for the open source jailer. fbcode builds this tree with
# Buck; this is the equivalent for a plain checkout, and the only build the
# open source repository ships.
#
#   make              build bpfjctl
#   make STATIC=1     build bpfjctl with no shared object dependencies
#   make signed       build statically, then fs-verity sign for bpfjctl
#   make cmd          same, for a bpfjcmd with its arguments, and optionally
#                     its policy, compiled in
#   make srv          same, for the socket activated bpfjsrv
#   make log          build bpfjlog, which drains the pinned BPF log ringbuf
#   make client       build bpfjclient, which needs no BPF toolchain
#   make signing-key  generate a development signing key and certificate
#   make clean        remove the build directory
#   make config       print the resolved toolchain and flags
#
# Requires clang (BPF codegen), bpftool, a C++20 compiler, libbpf with its
# headers, and a checkout of libarena. Set LIBBPF_CFLAGS / LIBBPF_LIBS to point
# at a libbpf that pkg-config does not know about, and LIBARENA to the libarena
# checkout (see below).
#
# Everything is written under $(BUILD); the source tree is never touched.

BUILD    ?= build
CXX      ?= g++
CLANG    ?= clang
BPFTOOL  ?= bpftool

# ---------------------------------------------------------------------------
# libbpf
# ---------------------------------------------------------------------------

LIBBPF_CFLAGS ?= $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS   ?= $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf)

# libbpf's headers are C, and in a C++ translation unit they trip -Wpedantic
# and -Wshadow dozens of times over anonymous structs, flexible array members
# and its *_opts helpers. -isystem silences those without softening the
# warnings that apply to this tree.
LIBBPF_INCLUDES := $(patsubst -I%,-isystem %,$(LIBBPF_CFLAGS))

# ---------------------------------------------------------------------------
# libarena
# ---------------------------------------------------------------------------

# The arena spin lock bpfj/lib/bpf/lock.h takes comes from libarena, which
# ships as source rather than as a package. Clone it and point LIBARENA at the
# checkout:
#
#   git clone https://github.com/libbpf/libarena ~/libarena
#   make LIBARENA=~/libarena
#
# Only the BPF objects read it, from $(LIBARENA)/libarena/include.
LIBARENA ?=
LIBARENA_INCLUDE := $(LIBARENA)/libarena/include

# ---------------------------------------------------------------------------
# Static linking
# ---------------------------------------------------------------------------

# STATIC=1 leaves the binary with no shared object dependencies at all, for
# deployments that sign the binary and would otherwise have to sign and ship
# every library it loads alongside it.
#
# This needs the static archives, which most distributions package apart from
# the shared ones: libbpf-static, elfutils-libelf-devel-static, zlib-static,
# libzstd-static, libstdc++-static, glibc-static. Version skew between
# libbpf.a and the libbpf headers is silent and does not survive to a link
# error, so install the static archive from the same libbpf as the -devel.
#
# Asking pkg-config for the closure beats naming libelf/zlib/zstd here: which
# of them libbpf actually pulls in depends on how it was configured.
LIBBPF_STATIC_LIBS ?= $(shell pkg-config --static --libs libbpf 2>/dev/null || echo -lbpf -lelf -lz -lzstd)

ifeq ($(STATIC),1)

# Static glibc is a hazard only for programs that resolve names, look up users
# or dlopen at runtime: those reach for NSS modules that were never in the
# archive, and fail at runtime rather than at link time. This tree does none of
# those, so the usual objection to -static does not apply to it.
STATICFLAGS := -static
STATICLIBS  := $(LIBBPF_STATIC_LIBS)

# gcc rejects -static -fsanitize=address outright, and the other runtimes are
# not shipped as archives either. Say so here rather than let it surface as a
# missing -lubsan several screens further down.
ifneq ($(SANITIZE),)
$(error STATIC=1 cannot be combined with SANITIZE=$(SANITIZE); build the sanitized binary without STATIC)
endif

else
STATICLIBS := $(LIBBPF_LIBS)
endif

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------

# The tree is C++20: concepts in bpfj/err, designated initialisers, <bit>.
CXXSTD ?= -std=gnu++20

# Deliberately not -Werror: a downstream build should not fail because a newer
# compiler grew a new warning. -Wno-missing-field-initializers because a
# partly-initialised `struct argp` is how argp is meant to be used, and the
# unnamed members are zero-initialised regardless.
WARNFLAGS ?= \
	-Wall \
	-Wextra \
	-Wpedantic \
	-Wshadow \
	-Wnon-virtual-dtor \
	-Wformat=2 \
	-Wcast-qual \
	-Wundef \
	-Wno-missing-field-initializers

OPTFLAGS ?= -O2 -g -fno-omit-frame-pointer

# SANITIZE=address,undefined
ifneq ($(SANITIZE),)
SANFLAGS := -fsanitize=$(SANITIZE) -fno-sanitize-recover=all
endif

# -I. so sources resolve "bpfj/..." and "ctl/..." against the repo root, and
# -I$(BUILD) so they resolve the generated skeleton at the same path the Buck
# build stages it under.
INCLUDES := -I. -I$(BUILD) $(LIBBPF_INCLUDES)

CXXFLAGS ?= $(CXXSTD) $(OPTFLAGS) $(WARNFLAGS) $(SANFLAGS)
LDFLAGS  ?= $(STATICFLAGS) $(SANFLAGS)
LDLIBS   ?= $(STATICLIBS)

# Mirrors the flags the kernel's own selftests use, which is what the Buck
# build follows too. -g is load-bearing: it is what emits the BTF that CO-RE
# and LSM attachment need, and stripping it breaks loading, not just debugging.
BPF_ARCH ?= $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')

# -target bpf leaves the host arch macro undefined, so glibc's headers cannot
# work out the word size and reach for <gnu/stubs-32.h>. Define it ourselves --
# jailer.bpf.c includes <errno.h>, so those headers are in the path.
BPF_ARCH_DEF ?= __$(shell uname -m)__

# A current bpftool writes a few hundred kfunc prototypes into vmlinux.h,
# generated from the kernel's own BTF, and they collide with the ones this
# tree and libbpf declare for themselves -- every .bpf.c then fails on
# conflicting types. bpftool guards that block for exactly this reason. An
# older bpftool, which never emitted the prototypes, does not notice the
# define.
BPF_CFLAGS ?= \
	-target bpf \
	-mcpu=v3 \
	-g \
	-O2 \
	-Wall \
	-Wno-compare-distinct-pointer-types \
	-fno-builtin \
	-Wno-unused-function \
	-DBPF_NO_KFUNC_PROTOTYPES \
	-D$(BPF_ARCH_DEF) \
	-D__TARGET_ARCH_$(BPF_ARCH)

# bpf_atomic.h includes <vmlinux.h> by bare name, hence the second include
# directory. Kept apart from BPF_CFLAGS so overriding that does not drop it.
BPF_LIBARENA_FLAGS = \
	-DENABLE_ATOMICS_TESTS \
	-DBPFJ_OSS_BUILD \
	-I$(LIBARENA_INCLUDE) \
	-I$(dir $(VMLINUX))

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

BPF_SRCS := \
	bpfj/enforce/bpf/jailer.bpf.c \
	bpfj/enforce/bpf/replace.bpf.c \
	bpfj/enforce/bpf/verity_enforce.bpf.c \
	bpfj/enforce/bpf/exec_enforce.bpf.c \
	bpfj/enforce/bpf/bpf_enforce.bpf.c \
	bpfj/enforce/bpf/kill_enforce.bpf.c \
	bpfj/enforce/bpf/ptrace_enforce.bpf.c \
	bpfj/enforce/bpf/proc_enforce.bpf.c \
	bpfj/enforce/bpf/lkm_enforce.bpf.c \
	bpfj/enforce/bpf/mq_enforce.bpf.c \
	bpfj/enforce/bpf/shm_enforce.bpf.c \
	bpfj/enforce/bpf/fs_enforce.bpf.c \
	bpfj/enforce/bpf/unix_enforce.bpf.c \
	bpfj/enforce/bpf/mount_enforce.bpf.c \
	bpfj/enforce/bpf/enroll.bpf.c

TEST_BPF_SRCS := \
	tests/bpf/const_map_test.bpf.c \
	tests/bpf/dyn_lru_test.bpf.c \
	tests/bpf/dyn_map_test.bpf.c \
	tests/bpf/glob_map_test.bpf.c \
	tests/bpf/heap_bpf_test.bpf.c \
	tests/bpf/lock_test.bpf.c \
	tests/bpf/mount_snapshot_test.bpf.c \
	tests/bpf/perf_map_test.bpf.c \
	tests/bpf/shared_ptr_test.bpf.c \
	tests/bpf/str_map_test.bpf.c \
	tests/bpf/vec_test.bpf.c

BPF_OBJS := $(BPF_SRCS:%.bpf.c=$(BUILD)/%.bpf.o)
BPF_DEPS := $(BPF_OBJS:.bpf.o=.bpf.d)
SKELS    := $(BPF_SRCS:%.bpf.c=$(BUILD)/%.skel.h)
TEST_BPF_OBJS := $(TEST_BPF_SRCS:%.bpf.c=$(BUILD)/%.bpf.o)
TEST_BPF_DEPS := $(TEST_BPF_OBJS:.bpf.o=.bpf.d)
TEST_SKELS    := $(TEST_BPF_SRCS:%.bpf.c=$(BUILD)/%.skel.h)
VMLINUX  := $(BUILD)/bpf/vmlinux/vmlinux.h

# Everything but the entry point. bpfjctl and bpfjcmd are the same program
# either side of where its arguments come from, so only main() differs.
COMMON_SRCS := \
	bpfj/lib/Base64.cpp \
	bpfj/lib/Fd.cpp \
	bpfj/lib/Privileges.cpp \
	bpfj/libbpf-cpp/BpfSkel.cpp \
	bpfj/fsverity/FsVerityFile.cpp \
	bpfj/fsverity/Keyring.cpp \
	bpfj/policy/Policy.cpp \
	bpfj/enforce/ArenaMap.cpp \
	bpfj/enforce/PodVars.cpp \
	bpfj/enforce/UnprivRoles.cpp \
	bpfj/enforce/EnrollGate.cpp \
	bpfj/enforce/Pins.cpp \
	bpfj/enforce/ScratchMapFds.cpp \
	bpfj/enforce/Jailer.cpp \
	bpfj/enforce/Replace.cpp \
	bpfj/enforce/VerityEnforcer.cpp \
	bpfj/enforce/ExecEnforcer.cpp \
	bpfj/enforce/BpfEnforcer.cpp \
	bpfj/enforce/KillEnforcer.cpp \
	bpfj/enforce/PtraceEnforcer.cpp \
	bpfj/enforce/ProcEnforcer.cpp \
	bpfj/enforce/LkmEnforcer.cpp \
	bpfj/enforce/MqEnforcer.cpp \
	bpfj/enforce/ShmEnforcer.cpp \
	bpfj/enforce/FsEnforcer.cpp \
	bpfj/enforce/UnixEnforcer.cpp \
	bpfj/enforce/MountEnforcer.cpp \
	bpfj/enforce/Pods.cpp \
	log/BpfLog.cpp \
	ctl/Dispatch.cpp \
	ctl/Options.cpp \
	ctl/PodPrinter.cpp \
	ctl/commands/Attach.cpp \
	ctl/commands/Check.cpp \
	ctl/commands/Detach.cpp \
	ctl/commands/Enroll.cpp \
	ctl/commands/List.cpp \
	ctl/commands/Replace.cpp \
	ctl/commands/Show.cpp \
	ctl/commands/Wrap.cpp

CTL_SRCS := ctl/Main.cpp
CMD_SRCS := cmd/Main.cpp

# bpfjsrv shares the enrollment path with bpfjctl and differs only in where a
# request comes from: a systemd socket rather than a command line.
SRV_SRCS := \
	srv/Server.cpp \
	srv/Main.cpp

LOG_SRCS := log/Main.cpp

# bpfjclient is the one binary here that links nothing else: srv/Client.h is
# header-only, which is the whole point of it.
CLIENT_SRCS := client/Main.cpp

# A third entry point, on the same footing as the two above: the harness
# brings its own main() and links everything else.
TEST_SRCS := \
	tests/BpfLogTest.cpp \
	tests/BpfEnforcerTest.cpp \
	tests/ConstMapTest.cpp \
	tests/CtlCommand.cpp \
	tests/CtlTest.cpp \
	tests/DynLruTest.cpp \
	tests/DynMapTest.cpp \
	tests/Enforce.cpp \
	tests/EnrollGateTest.cpp \
	tests/ExecEnforcerTest.cpp \
	tests/FsVerityFileTest.cpp \
	tests/FsEnforcerTest.cpp \
	tests/GlobMapTest.cpp \
	tests/Harness.cpp \
	tests/HarnessTest.cpp \
	tests/HeapBpfTest.cpp \
	tests/HeapTest.cpp \
	tests/KeyringTest.cpp \
	tests/KillEnforcerTest.cpp \
	tests/LkmEnforcerTest.cpp \
	tests/LockTest.cpp \
	tests/MqEnforcerTest.cpp \
	tests/MountSnapshotTest.cpp \
	tests/PerfMapTest.cpp \
	tests/SharedPtrTest.cpp \
	tests/ShmEnforcerTest.cpp \
	tests/StrMapTest.cpp \
	tests/UnixEnforcerTest.cpp \
	tests/MountEnforcerTest.cpp \
	tests/Main.cpp \
	tests/PtraceEnforcerTest.cpp \
	tests/ProcEnforcerTest.cpp \
	tests/PolicyTest.cpp \
	tests/ProtocolTest.cpp \
	tests/VecTest.cpp \
	srv/Server.cpp \
	tests/VerityEnforcerTest.cpp

SRCS := $(COMMON_SRCS) $(CTL_SRCS) $(CMD_SRCS) $(SRV_SRCS) $(LOG_SRCS) $(CLIENT_SRCS) \
	$(TEST_SRCS)

COMMON_OBJS := $(COMMON_SRCS:%.cpp=$(BUILD)/%.o)
CTL_OBJS    := $(CTL_SRCS:%.cpp=$(BUILD)/%.o)
CMD_OBJS    := $(CMD_SRCS:%.cpp=$(BUILD)/%.o)
SRV_OBJS    := $(SRV_SRCS:%.cpp=$(BUILD)/%.o)
LOG_OBJS    := $(LOG_SRCS:%.cpp=$(BUILD)/%.o)
CLIENT_OBJS := $(CLIENT_SRCS:%.cpp=$(BUILD)/%.o)
TEST_OBJS   := $(TEST_SRCS:%.cpp=$(BUILD)/%.o)

OBJS := $(COMMON_OBJS) $(CTL_OBJS) $(CMD_OBJS) $(SRV_OBJS) $(LOG_OBJS) $(CLIENT_OBJS) \
	$(TEST_OBJS)
DEPS := $(OBJS:.o=.d)

BIN     := $(BUILD)/bpfjctl
CMD_BIN := $(BUILD)/bpfjcmd
SRV_BIN := $(BUILD)/bpfjsrv
LOG_BIN := $(BUILD)/bpfjlog
CLIENT_BIN := $(BUILD)/bpfjclient
TEST_BIN := $(BUILD)/bpfjtest

# Whether the last link was static is not recorded in any object file, so a
# timestamp comparison cannot see that STATIC changed between runs and the
# binary gets reused in whichever mode it was built last. Record the mode and
# hang the link off it.
LINKMODE     := $(BUILD)/.linkmode
LINKMODE_NOW := $(if $(filter 1,$(STATIC)),static,dynamic)
LIBARENA_CONFIG := $(BUILD)/.libarena-config

# ---------------------------------------------------------------------------
# bpfjcmd
# ---------------------------------------------------------------------------

# bpfjcmd is bpfjctl with its arguments compiled in and argc/argv ignored.
# Because the arguments live in the binary they fall under the fs-verity
# digest that `make cmd` signs, so they cannot be swapped for others without
# invalidating the signature. They are still plainly readable in the binary --
# this buys integrity, not secrecy.
#
#   make cmd CMD_ARGS="attach /etc/bpfj/policy.toml" SIGNING_KEY=... SIGNING_CERT=...
#
# CMD_ARGS splits on whitespace, which cannot express an argument containing
# one. CMD_ARGV_RAW takes a C initialiser list instead for that case:
#
#   make cmd CMD_ARGV_RAW='"attach", "/etc/bpfj/policy file.toml"' ...
#
# CMD_POLICY compiles a policy file in alongside them, and closes what the
# arguments alone leave open: signing `attach /etc/bpfj/policy.toml` fixes
# which path is read and not what is in it, so whoever can write that file
# rewrites the policy -- the `certs` trust store included -- against a
# signature that still verifies. A policy in rodata cannot be changed without
# invalidating the digest. Readable with `strings` either way; this is
# integrity, not secrecy.
#
#   make cmd CMD_ARGS=attach-compiled CMD_POLICY=etc/policy.toml SIGNING_KEY=...
#
# The command has to be one of the -compiled ones, which take no path and read
# what was built in. They are separate commands rather than a mode of `attach`
# so that which policy a signed binary enforces is legible in the command it
# carries instead of depending on how it was built.
#
# CMD_ROLE claims a role for the binary, which is how it becomes subject to
# one. A signature says a binary is trusted; the role is what the policy has
# an opinion about, and without it nothing connects the two -- the fs-verity
# enforcer only checks a binary whose role names `enforce-binary-certs`, so
# an unclaimed binary is not checked at all.
#
#   make cmd CMD_ARGS=replace-compiled CMD_POLICY=etc/policy.toml \
#            CMD_ROLE=bpfjailer SIGNING_KEY=... SIGNING_CERT=...

CMD_SEQ      ?=
CMD_ARGS     ?=
CMD_ARGV_RAW ?=
CMD_POLICY   ?=
CMD_ROLE     ?=

CMD_ARGS_H   := $(BUILD)/cmd/Args.h
CMD_POLICY_H := $(BUILD)/cmd/Policy.h

CMD_ARGV_INIT := $(if $(CMD_ARGV_RAW),$(CMD_ARGV_RAW),$(foreach a,$(CMD_ARGS),"$(a)",))

# The commands that read a compiled-in policy, for the checks in `cmd`.
CMD_POLICY_READERS := attach-compiled replace-compiled check-compiled
CMD_FIRST_ARG      := $(firstword $(CMD_ARGS))

# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

# `make signed` produces a statically linked bpfjctl carrying a PKCS#7
# signature over its fs-verity digest, in the shape bpfjailer's BPF side
# verifies: bpfj_check_fsverity_pkcs7() reads the signature from the
# user.bpfj.sig xattr, asks the kernel for the file's fs-verity digest, and
# passes both to bpf_verify_pkcs7_signature() against a keyring.
#
# What is signed is the bare digest -- 32 bytes for sha256 -- and not the
# fsverity_formatted_digest that the kernel's own builtin signatures use. That
# is why this computes the digest and signs it separately instead of reaching
# for `fsverity sign`, which would produce the other thing.
#
# The signature alone does not make the binary runnable under bpfjailer. Two
# things have to happen wherever it is deployed:
#
#   - fs-verity has to be enabled on the file, or the kernel has no digest to
#     hand to BPF and verification fails with REASON_NO_DIGEST. It cannot be
#     enabled here: enabling freezes the file permanently, and the build tree
#     is often not on a filesystem that supports it at all.
#   - SIGNING_CERT has to be in the keyring for the role being verified,
#     which is policy configuration rather than anything a build can do.
#
# Whatever packages the result has to preserve extended attributes; for tar
# that is --xattrs --xattrs-include='user.*'.
#
# SIGNDIR has to be on a filesystem that supports user xattrs, since that is
# where the signature ends up. The default sits under $(BUILD) like everything
# else, which is right for a plain checkout but not for a virtualised one --
# override it there.

SIGNING_KEY   ?=
SIGNING_CERT  ?=
SIGNDIR       ?= $(BUILD)/signed
FSVERITY      ?= fsverity
OPENSSL       ?= openssl
SETFATTR      ?= setfattr
SIGN_HASH_ALG ?= sha256

# The xattr bpfjailer reads the signature from, spelled as
# BPFJ_EXEC_SIG_XATTR in bpfj/enforce/bpf/types.h.
SIGN_XATTR ?= user.bpfj.sig

# And the one it reads a claimed role from, BPFJ_EXEC_POLICY_XATTR in the same
# header. The value goes into a char[ROLE_ID_LEN] with room for a terminator,
# so a longer role is truncated to something the policy does not name.
ROLE_XATTR   ?= user.bpfj.policy.exec

# BPFJ_EXEC_SEQ_XATTR. Unlike the role, this one is covered by the signature:
# the signed payload is the digest with the sequence number appended, so a
# rewritten seq fails verification rather than raising the binary's version.
SEQ_XATTR    ?= user.bpfj.seq
ROLE_MAX_LEN ?= 15

# BPFJ_SIG_BUF_SIZE. A larger signature is silently unreadable to BPF, so it
# is worth failing here rather than at exec time.
SIGN_MAX_BYTES ?= 16384

SIGNED_CA := $(SIGNDIR)/signer.pem

ifeq ($(SIGN_HASH_ALG),sha512)
SIGN_DIGEST_BYTES := 64
else
SIGN_DIGEST_BYTES := 32
endif

# Both signing targets stage their output under $(SIGNDIR) beside the binary's
# own name, so bpfjctl and bpfjcmd can be signed into the same directory.
signed-bin    = $(SIGNDIR)/$(notdir $(1))
signed-digest = $(SIGNDIR)/$(notdir $(1)).digest
signed-sig    = $(SIGNDIR)/$(notdir $(1)).p7s

# Everything that can be settled before anything is built. Worth its own macro
# so a missing key or an unusable SIGNDIR costs nothing: both targets relink
# from scratch, and finding out afterwards wastes the whole build.
define sign-preflight
	@if [ -z "$(SIGNING_KEY)" ] || [ -z "$(SIGNING_CERT)" ]; then \
		echo "$@: set SIGNING_KEY (private key, PEM) and SIGNING_CERT (certificate, DER)" >&2; \
		echo "    \`make signing-key\` generates a development pair" >&2; \
		exit 1; \
	fi
	@mkdir -p $(SIGNDIR)
	@probe=$(SIGNDIR)/.xattr-probe; : > $$probe; \
	if ! $(SETFATTR) -n user.bpfj.probe -v 1 $$probe 2>/dev/null; then \
		rm -f $$probe; \
		echo "$@: $(SIGNDIR) is on a filesystem with no user xattr support, and the" >&2; \
		echo "    signature has nowhere else to go. Point SIGNDIR at ext4 or btrfs:" >&2; \
		echo "      make $@ SIGNDIR=/var/tmp/bpfj-signed ..." >&2; \
		exit 1; \
	fi; \
	rm -f $$probe
endef

# Signs $(1), which has to be statically linked already. The readelf check is
# not redundant with $(LINKMODE): it is the one thing here that reads the
# binary itself, and signing one with shared object dependencies would defeat
# the point of signing it.
#
# $(2), when set, is the sequence number: appended to the digest so the
# signature covers the pair, and written to the xattr the enforcer reads it
# back from. printf gives the 8 bytes big-endian that bpfj_get_seq_be expects.
#
# No comma in the text of the `$(if $(2),...)` lines below: make splits on the
# first one it sees at that level, and the tail becomes an else-branch that
# expands when $(2) is empty -- as a fragment of a sentence with an
# unterminated quote, which the shell then refuses to parse.
#
# Comments cannot go inside the define: make keeps them in the variable's
# value, and every line of that value is handed to the shell as a recipe line.
define sign-binary
	@needed=$$(readelf -d $(1) | grep -c NEEDED || true); \
	if [ "$$needed" -ne 0 ]; then \
		echo "$@: $(1) still has $$needed shared object dependencies, refusing to sign" >&2; \
		exit 1; \
	fi
	cp $(1) $(call signed-bin,$(1))
	chmod u+w $(call signed-bin,$(1))
	set -o pipefail; $(FSVERITY) digest $(call signed-bin,$(1)) --hash-alg=$(SIGN_HASH_ALG) --compact \
		| tr -d '\n' | xxd -p -r > $(call signed-digest,$(1))
	@size=$$(stat -c%s $(call signed-digest,$(1))); \
	if [ "$$size" -ne $(SIGN_DIGEST_BYTES) ]; then \
		echo "$@: digest is $$size bytes, expected $(SIGN_DIGEST_BYTES) for $(SIGN_HASH_ALG)" >&2; \
		exit 1; \
	fi
	$(if $(2),printf '%016x' $(2) | xxd -p -r >> $(call signed-digest,$(1)))
	$(OPENSSL) cms -sign -binary -in $(call signed-digest,$(1)) \
		-signer $(SIGNING_CERT) -inkey $(SIGNING_KEY) \
		-outform der -md $(SIGN_HASH_ALG) -nosmimecap -out $(call signed-sig,$(1))
	@size=$$(stat -c%s $(call signed-sig,$(1))); \
	if [ "$$size" -ge $(SIGN_MAX_BYTES) ]; then \
		echo "$@: signature is $$size bytes, at or over the $(SIGN_MAX_BYTES) BPF can read" >&2; \
		exit 1; \
	fi
	$(SETFATTR) -n $(SIGN_XATTR) -v "0s$$(base64 -w0 $(call signed-sig,$(1)))" $(call signed-bin,$(1))
	$(if $(2),$(SETFATTR) -n $(SEQ_XATTR) -v "0s$$(printf '%016x' $(2) | xxd -p -r | base64 -w0)" $(call signed-bin,$(1)))
	$(OPENSSL) x509 -inform DER -in $(SIGNING_CERT) -out $(SIGNED_CA)
	$(OPENSSL) cms -verify -binary -inform DER -purpose any -partial_chain \
		-content $(call signed-digest,$(1)) -in $(call signed-sig,$(1)) -CAfile $(SIGNED_CA) -out /dev/null
	@echo
	@echo "Signed $(call signed-bin,$(1))"
	@echo "  $(SIGN_HASH_ALG) digest  $$(xxd -p -c 64 $(call signed-digest,$(1)))"
	@echo "  signature     $$(stat -c%s $(call signed-sig,$(1))) bytes, in the $(SIGN_XATTR) xattr"
	$(if $(2),@echo "  sequence      $(2) in the $(SEQ_XATTR) xattr -- signed over with the digest")
	@echo "  still needed  fs-verity enabled on the deployed copy, and $(SIGNING_CERT) in the verifying keyring"
endef

# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

# cmd and srv name directories as well as targets, so without .PHONY make would
# find those directories up to date and build nothing.
.PHONY: all clean config signed signing-key client cmd srv log test libarena-check FORCE
all: $(BIN)

FORCE:

# The skeletons and BPF objects are only ever reached through a pattern rule,
# which make treats as intermediate and deletes on the way out -- regenerating
# every one of them on the next build. They are outputs, not scratch.
.SECONDARY: $(BPF_OBJS) $(SKELS) $(TEST_BPF_OBJS) $(TEST_SKELS)

# Generated from the running kernel's BTF. Checking one in would be
# reproducible but would go stale against the kernel actually being run; CO-RE
# means a vmlinux.h newer than the target kernel is still fine.
$(VMLINUX):
	@mkdir -p $(dir $@)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# jailer.bpf.c includes <bpf/vmlinux/vmlinux.h>, so the generated header is
# staged at that path under $(BUILD) and reached through -I$(BUILD). Same
# spelling in both builds.
# -MT names the real object rather than the .tmp clang is told to write, so
# the generated dependency applies to the target make actually builds. Without
# these an edit to a header rebuilds nothing, and the stale skeleton that
# leaves behind looks like the source change simply had no effect.
$(BUILD)/%.bpf.o: %.bpf.c $(VMLINUX) $(LIBARENA_CONFIG) | libarena-check
	@mkdir -p $(dir $@)
	$(CLANG) $(BPF_CFLAGS) $(BPF_LIBARENA_FLAGS) $(INCLUDES) -MMD -MP -MT $@ -MF $(@:.bpf.o=.bpf.d) -c $< -o $@.tmp
	$(BPFTOOL) gen object $@ $@.tmp
	@rm -f $@.tmp

# Order-only, so it fails the build up front with instructions rather than as
# a missing-header error deep in a BPF compile, without forcing a rebuild.
libarena-check:
	@if [ ! -f "$(LIBARENA_INCLUDE)/bpf_arena_spin_lock.h" ]; then \
		echo "libarena not found at '$(LIBARENA)'. Clone it and set LIBARENA:" >&2; \
		echo "  git clone https://github.com/libbpf/libarena ~/libarena" >&2; \
		echo "  make LIBARENA=~/libarena" >&2; \
		exit 1; \
	elif ! grep -q 'arena_spinlock_t __arg_arena __arena \*lock' \
		"$(LIBARENA_INCLUDE)/bpf_arena_spin_lock.h"; then \
		echo "libarena at '$(LIBARENA)' lacks arena argument tags." >&2; \
		echo "Update libarena or use the fbsource vendored revision." >&2; \
		exit 1; \
	fi

$(BUILD)/%.skel.h: $(BUILD)/%.bpf.o
	@mkdir -p $(dir $@)
	$(BPFTOOL) gen skeleton $< > $@

# Every object waits on every skeleton: Jailer.cpp includes them, and the
# others reach them through Jailer.h's translation units often enough that
# ordering it once here is simpler than tracking which do.
$(BUILD)/%.o: %.cpp $(SKELS)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -MMD -MP -c $< -o $@

$(BUILD)/tests/GlobMapTest.o: $(TEST_SKELS)
$(BUILD)/tests/MountSnapshotTest.o: $(TEST_SKELS)
$(BUILD)/tests/ConstMapTest.o: $(TEST_SKELS)
$(BUILD)/tests/DynLruTest.o: $(TEST_SKELS)
$(BUILD)/tests/DynMapTest.o: $(TEST_SKELS)
$(BUILD)/tests/HeapBpfTest.o: $(TEST_SKELS)
$(BUILD)/tests/LockTest.o: $(TEST_SKELS)
$(BUILD)/tests/PerfMapTest.o: $(TEST_SKELS)
$(BUILD)/tests/SharedPtrTest.o: $(TEST_SKELS)
$(BUILD)/tests/StrMapTest.o: $(TEST_SKELS)
$(BUILD)/tests/VecTest.o: $(TEST_SKELS)

# Rewritten only when the mode actually changes, so an unchanged mode leaves
# the mtime alone and does not drag the binary through a needless relink.
$(LINKMODE): FORCE
	@mkdir -p $(dir $@)
	@if [ ! -f $@ ] || [ "$$(cat $@)" != "$(LINKMODE_NOW)" ]; then \
		echo "$(LINKMODE_NOW)" > $@; \
	fi

# LIBARENA is a command-line path, so dependency files alone cannot tell make
# that an existing BPF object was compiled against a different checkout.
$(LIBARENA_CONFIG): FORCE
	@mkdir -p $(dir $@)
	@if [ ! -f $@ ] || [ "$$(cat $@)" != "$(LIBARENA_INCLUDE)" ]; then \
		echo "$(LIBARENA_INCLUDE)" > $@; \
	fi

# Rewritten only when the arguments actually change, for the same reason as
# $(LINKMODE): CMD_ARGS lives on the command line, not in any file the
# timestamp comparison can see.
$(CMD_ARGS_H): FORCE
	@mkdir -p $(dir $@)
	@{ echo '// @generated by the bpfjailer_oss Makefile from CMD_ARGS -- do not edit'; \
	   echo '#pragma once'; \
	   echo ''; \
	   echo 'static const char* const kBpfjcmdArgv[] = {"$(notdir $(CMD_BIN))", $(CMD_ARGV_INIT)};'; \
	 } > $@.tmp
	@if cmp -s $@.tmp $@; then rm -f $@.tmp; else mv $@.tmp $@; fi

# A byte array rather than a string literal: a policy is arbitrary text, and
# one holding a quote or a backslash would come out of a literal as something
# other than what was signed. xxd is already needed to sign, so this costs no
# new build dependency. The trailing zero is what lets main() take the length
# as sizeof less one, and leaves an unset CMD_POLICY a zero-length array
# rather than a special case.
#
# CMD_POLICY is a prerequisite so editing the policy rebuilds, and FORCE is
# there for the same reason as above: which file CMD_POLICY names lives on the
# command line, where no timestamp comparison can see it change.
$(CMD_POLICY_H): $(CMD_POLICY) FORCE
	@mkdir -p $(dir $@)
	@{ echo '// @generated by the bpfjailer_oss Makefile from CMD_POLICY -- do not edit'; \
	   echo '#pragma once'; \
	   echo ''; \
	   echo 'static const char kBpfjcmdPolicy[] = {'; \
	   policy='$(CMD_POLICY)'; \
	   if [ -s "$$policy" ]; then xxd -i < "$$policy"; echo ','; fi; \
	   echo '0};'; \
	 } > $@.tmp
	@if cmp -s $@.tmp $@; then rm -f $@.tmp; else mv $@.tmp $@; fi

$(BUILD)/cmd/Main.o: $(CMD_ARGS_H) $(CMD_POLICY_H)

$(BIN): $(COMMON_OBJS) $(CTL_OBJS) $(LINKMODE)
	$(CXX) $(LDFLAGS) $(COMMON_OBJS) $(CTL_OBJS) $(LDLIBS) -o $@

$(CMD_BIN): $(COMMON_OBJS) $(CMD_OBJS) $(LINKMODE)
	$(CXX) $(LDFLAGS) $(COMMON_OBJS) $(CMD_OBJS) $(LDLIBS) -o $@

$(SRV_BIN): $(COMMON_OBJS) $(SRV_OBJS) $(LINKMODE)
	$(CXX) $(LDFLAGS) $(COMMON_OBJS) $(SRV_OBJS) $(LDLIBS) -o $@

$(LOG_BIN): $(COMMON_OBJS) $(LOG_OBJS) $(LINKMODE)
	$(CXX) $(LDFLAGS) $(COMMON_OBJS) $(LOG_OBJS) $(LDLIBS) -o $@

# Spelled out rather than left to the pattern rule above, which waits on every
# BPF skeleton: a caller of srv/Client.h should not need clang or bpftool.
$(BUILD)/client/%.o: client/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -MMD -MP -c $< -o $@

# No COMMON_OBJS and no LDLIBS for the same reason: libc is the whole of it.
$(CLIENT_BIN): $(CLIENT_OBJS) $(LINKMODE)
	$(CXX) $(LDFLAGS) $(CLIENT_OBJS) -o $@

client: $(CLIENT_BIN)

log: $(LOG_BIN)

$(TEST_BIN): $(COMMON_OBJS) $(TEST_OBJS) $(LINKMODE)
	$(CXX) $(LDFLAGS) $(COMMON_OBJS) $(TEST_OBJS) $(LDLIBS) -o $@

# Running the tests needs root -- each one unshares a mount namespace and
# mounts a bpffs. Building them does not, and `sudo make test` would leave
# every object under $(BUILD) owned by root with the next plain `make` unable
# to overwrite them. So the build half runs as whoever invoked make and only
# the binary is escalated. Set SUDO= to skip it when already privileged by
# other means, or SUDO="sudo -n" to fail rather than prompt.
SUDO ?= $(if $(filter 0,$(shell id -u)),,sudo)
TEST_ARGS ?=

test: $(TEST_BIN) $(LOG_BIN)
	$(SUDO) $(TEST_BIN) $(TEST_ARGS)

signed:
	$(call sign-preflight)
	$(MAKE) STATIC=1 $(BIN)
	$(call sign-binary,$(BIN))

cmd:
	@if [ -z "$(CMD_ARGS)$(CMD_ARGV_RAW)" ]; then \
		echo "cmd: set CMD_ARGS to the command to build in, e.g." >&2; \
		echo "       make cmd CMD_ARGS=\"attach /etc/bpfj/policy.toml\" ..." >&2; \
		echo "     a bpfjcmd with no command in it would do nothing but fail" >&2; \
		exit 1; \
	fi
	@if [ -n "$(CMD_POLICY)" ] && [ ! -s "$(CMD_POLICY)" ]; then \
		echo "cmd: CMD_POLICY=$(CMD_POLICY) is missing or empty" >&2; \
		exit 1; \
	fi
# Truncation here would be silent and would claim a role the policy does not
# name, which reads as "unclaimed" rather than as an error at exec time.
	@if [ -n "$(CMD_ROLE)" ] && [ $$(printf %s "$(CMD_ROLE)" | wc -c) -gt $(ROLE_MAX_LEN) ]; then \
		echo "cmd: CMD_ROLE=$(CMD_ROLE) is longer than $(ROLE_MAX_LEN) bytes" >&2; \
		exit 1; \
	fi
	@if [ -n "$(CMD_ROLE)" ] && [ -n "$(CMD_POLICY)" ] && \
	   ! grep -qE "^[[:space:]]+$(CMD_ROLE):[[:space:]]*$$" "$(CMD_POLICY)"; then \
		echo "cmd: warning: CMD_ROLE=$(CMD_ROLE) is not a role in $(CMD_POLICY)" >&2; \
		echo "     the binary would claim a role nothing has a policy for" >&2; \
	fi
# The two halves have to agree, and the command name is what says so. A
# -compiled command with nothing compiled in fails at every run; a policy
# compiled in for a command that does not read one is signed in and ignored.
# Matched whole-token rather than with grep -w, which counts `attach` a word
# of `attach-compiled` because the hyphen ends one.
	@case " $(CMD_POLICY_READERS) " in \
	  *" $(CMD_FIRST_ARG) "*) \
	    if [ -z "$(CMD_POLICY)" ]; then \
	      echo "cmd: '$(CMD_FIRST_ARG)' reads a compiled-in policy, but CMD_POLICY is unset" >&2; \
	      echo "     set CMD_POLICY, or build in '$(patsubst %-compiled,%,$(CMD_FIRST_ARG)) PATH' instead" >&2; \
	      exit 1; \
	    fi ;; \
	  *) \
	    if [ -n "$(CMD_POLICY)" ] && [ -n "$(CMD_ARGS)" ]; then \
	      echo "cmd: warning: CMD_POLICY is set, but '$(CMD_FIRST_ARG)' reads no compiled-in policy" >&2; \
	      echo "     the commands that do are: $(CMD_POLICY_READERS)" >&2; \
	    fi ;; \
	esac
	$(call sign-preflight)
	$(MAKE) STATIC=1 $(BIN) $(CMD_BIN)
# bpfjcmd cannot check its own policy -- it ignores argv by construction -- so
# bpfjctl, which shares every object with it and differs only in the link,
# does it. Worth the extra link: a signed binary carrying a policy that does
# not parse fails at attach time on a host, where it can no longer be changed.
	$(if $(CMD_POLICY),$(BIN) check $(CMD_POLICY))
	$(call sign-binary,$(CMD_BIN),$(CMD_SEQ))
# After signing, because fs-verity covers the file's contents and an xattr is
# not part of them -- the role can go on, or be changed, without invalidating
# the signature. That is why the role is not what authorises anything: the
# signature is, and the role only decides which policy applies.
	$(if $(CMD_ROLE),$(SETFATTR) -n $(ROLE_XATTR) -v "$(CMD_ROLE)" $(call signed-bin,$(CMD_BIN)))
# No comma in the text: make splits $(if) on the first one it sees at this
# level, and the tail would become an else-branch that prints when CMD_ROLE
# is empty.
	$(if $(CMD_ROLE),@echo "  role          $(CMD_ROLE) in the $(ROLE_XATTR) xattr")

# bpfjsrv is started by systemd for every enrollment, so it is the binary most
# worth signing: a jail is only as trustworthy as whatever hands out roles.
# Static for the same reason as the others, and because linking libsystemd for
# the two environment variables the socket protocol is would have put a shared
# object back under a signature that covers only this file.
srv:
	$(call sign-preflight)
	$(MAKE) STATIC=1 $(SRV_BIN)
	$(call sign-binary,$(SRV_BIN))
	@echo "  install with  srv/bpfjsrv.socket and srv/bpfjsrv@.service"

# Mirrors what bpfjailer's own tests sign with, down to the DER certificate:
# that is the form Keyring::addPKey() loads into a keyring. Both land under
# $(BUILD), so `make clean` takes the key with it.
signing-key:
	@if [ -e $(SIGNDIR)/dev_key.pem ] || [ -e $(SIGNDIR)/dev_cert.der ]; then \
		echo "signing-key: $(SIGNDIR) already holds a key pair, refusing to overwrite it" >&2; \
		exit 1; \
	fi
	@mkdir -p $(SIGNDIR)
	$(OPENSSL) genrsa -out $(SIGNDIR)/dev_key.pem 2048
	chmod 600 $(SIGNDIR)/dev_key.pem
	$(OPENSSL) req -new -x509 -key $(SIGNDIR)/dev_key.pem \
		-out $(SIGNDIR)/dev_cert.der -outform der -days 365 \
		-subj "/CN=bpfjctl development signing key"
	@echo
	@echo "make signed SIGNING_KEY=$(SIGNDIR)/dev_key.pem SIGNING_CERT=$(SIGNDIR)/dev_cert.der"

config:
	@echo "CXX         = $(CXX)"
	@echo "CLANG       = $(CLANG)"
	@echo "BPFTOOL     = $(BPFTOOL)"
	@echo "LIBARENA    = $(if $(LIBARENA),$(LIBARENA),(unset))"
	@echo "BUILD       = $(BUILD)"
	@echo "BPF_ARCH    = $(BPF_ARCH)"
	@echo "STATIC      = $(if $(filter 1,$(STATIC)),1,0)"
	@echo "CXXFLAGS    = $(CXXFLAGS)"
	@echo "INCLUDES    = $(INCLUDES)"
	@echo "LDFLAGS     = $(LDFLAGS)"
	@echo "LDLIBS      = $(LDLIBS)"
	@echo "FSVERITY    = $(FSVERITY)"
	@echo "OPENSSL     = $(OPENSSL)"
	@echo "SIGN_HASH   = $(SIGN_HASH_ALG)"
	@echo "SIGNING_KEY = $(if $(SIGNING_KEY),$(SIGNING_KEY),(unset))"
	@echo "SIGNING_CERT= $(if $(SIGNING_CERT),$(SIGNING_CERT),(unset))"
	@echo "CMD_ARGV    = $(if $(CMD_ARGV_INIT),$(CMD_ARGV_INIT),(unset))"
	@echo "CMD_POLICY  = $(if $(CMD_POLICY),$(CMD_POLICY),(unset))"
	@echo "CMD_ROLE    = $(if $(CMD_ROLE),$(CMD_ROLE),(unset))"

clean:
	rm -rf $(BUILD)

-include $(DEPS)
-include $(BPF_DEPS)
-include $(TEST_BPF_DEPS)
