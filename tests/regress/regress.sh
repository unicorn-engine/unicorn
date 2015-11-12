#!/bin/sh


./map_crash map_write
./sigill sigill2
./block_test
./ro_mem_test nr_mem_test
./timeout_segfault
./rep_movsb
./mem_unmap
./mem_protect
./mem_exec
./mem_map_large
