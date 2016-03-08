
CFLAGS += -I../../include

ifeq (MING,$(findstring MING,$(shell uname -s)))
LDFLAGS += ../../unicorn.lib $(shell pkg-config --libs glib-2.0) -lpthread -lm
else
LDFLAGS += ../../libunicorn.a $(shell pkg-config --libs glib-2.0) -lpthread -lm
endif

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
TESTS += x86_16_segfault
TESTS += mips_invalid_read_of_size_4_when_tracing
TESTS += invalid_read_in_tb_flush_x86_64
TESTS += sparc_jump_to_zero
TESTS += mips_delay_slot_code_hook
TESTS += mem_nofree
TESTS += rw_hookstack
TESTS += threaded_emu_start
TESTS += emu_stop_in_hook_overrun
TESTS += mips_branch_likely_issue
TESTS += hook_extrainvoke
TESTS += sysenter_hook_x86
TESTS += emu_clear_errors
TESTS += mem_fuzz
TESTS += fs_gs_size

all: $(TESTS)

clean:
	rm -f $(TESTS)

%: %.c
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

.PHONY: all clean
