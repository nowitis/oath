CLIENTAPP = oath
OBJCOPY ?= llvm-objcopy

P := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
LIBDIR ?= $(P)/../tkey-libs
LIBCRYPTO_DIR ?= $(P)/../tkey-crypto

CC = clang

INCLUDE=$(LIBDIR)/include

# If you want libcommon's qemu_puts() et cetera to output something on our QEMU
# debug port, remove -DNODEBUG below
CFLAGS = -target riscv32-unknown-none-elf -march=rv32iczmmul -mabi=ilp32 -mcmodel=medany \
   -static -std=gnu99 -O2 -ffast-math -fno-common -fno-builtin-printf \
   -fno-builtin-putchar -nostdlib -mno-relax -flto -g \
   -Wall -Werror=implicit-function-declaration \
   -I $(INCLUDE) -I $(LIBDIR) -I $(LIBCRYPTO_DIR)/include \
   -DNODEBUG

AS = clang
ASFLAGS = -target riscv32-unknown-none-elf -march=rv32iczmmul -mabi=ilp32 -mcmodel=medany -mno-relax

LDFLAGS=-T $(LIBDIR)/app.lds -L $(LIBDIR)/libcommon/ -lcommon -L $(LIBDIR)/libcrt0/ -lcrt0 \
	-L $(LIBCRYPTO_DIR)/libarithmetic/ -larithmetic -L $(LIBCRYPTO_DIR)/libsha/ -lsha

RM=/bin/rm


.PHONY: all
all: deviceapp client
both: podman-deviceapp client

deviceapp: app/app.bin
client: $(CLIENTAPP)

# Turn elf into bin for device
%.bin: %.elf
	$(OBJCOPY) --input-target=elf32-littleriscv --output-target=binary $^ $@
	chmod a-x $@

show-%-hash: %/app.bin
	cd $$(dirname $^) && sha512sum app.bin

APP_OBJS = app/main.o app/app_proto.o app/assert.o app/system.o app/helpers.o app/oath/oath.o
app/app.elf: $(LIBS) $(CRYPTOLIBS) $(APP_OBJS)
	$(CC) $(CFLAGS) $(APP_OBJS) $(LDFLAGS) -L $(LIBDIR)/monocypher -lmonocypher -L app/lib -lsha -o $@
$(APP_OBJS): $(INCLUDE)/tk1_mem.h app/app_proto.h app/assert.h app/helpers.h app/oath/oath.h

.PHONY: clean
clean:
	$(RM) -f app/oath/*.o
	$(RM) -f app/app.bin app/app.elf app/*.o
	$(RM) -f $(CLIENTAPP) cmd/app.bin

# Uses ../.clang-format
FMTFILES=app/*.[ch]

.PHONY: fmt
fmt:
	clang-format --dry-run --ferror-limit=0 $(FMTFILES)
	clang-format --verbose -i $(FMTFILES)
.PHONY: checkfmt
checkfmt:
	clang-format --dry-run --ferror-limit=0 --Werror $(FMTFILES)

podman-deviceapp:
	podman run --rm --mount type=bind,source=$(CURDIR),target=/src --mount type=bind,source=$(CURDIR)/../tkey-libs,target=/tkey-libs --mount type=bind,source=$(CURDIR)/../tkey-crypto,target=/tkey-crypto -w /src -it ghcr.io/tillitis/tkey-builder:2 make -j deviceapp

# .PHONY to let go-build handle deps and rebuilds
.PHONY: $(CLIENTAPP)
$(CLIENTAPP): app/app.bin
	cp -af app/app.bin cmd/app.bin
	CGO_CFLAGS="-I$(LIBDIR) -I$(INCLUDE) -I$(P)/app" go build -o $(CLIENTAPP) ./cmd

.PHONY: lint
lint:
	$(MAKE) -C gotools
	GOOS=linux   ./gotools/golangci-lint run
	GOOS=windows ./gotools/golangci-lint run
