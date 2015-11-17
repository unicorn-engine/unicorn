CFLAGS += -I../include
LDFLAGS += ../../libunicorn.a $(shell pkg-config --libs glib-2.0) -lpthread -lm

TESTS = map_crash map_write
TESTS += sigill sigill2
TESTS += block_test
TESTS += ro_mem_test nr_mem_test
TESTS += timeout_segfault
TESTS += rep_movsb
TESTS += mem_unmap
TESTS += mem_double_unmap
TESTS += mem_protect
TESTS += mem_exec
TESTS += mips_kseg0_1
TESTS += eflags_nosync
TESTS += 00opcode_uc_crash
TESTS += eflags_noset
TESTS += mem_map_large
TESTS += invalid_read_in_cpu_tb_exec
TESTS += invalid_write_in_cpu_tb_exec_x86_64

all: $(TESTS)

clean:
	rm -f $(TESTS)

%: %.c
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

.PHONY: all clean
