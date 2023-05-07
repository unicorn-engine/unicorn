/*

Java bindings for the Unicorn Emulator Engine

Copyright(c) 2015 Chris Eagle, 2023 Robert Xiao

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
version 2 as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

*/

package unicorn;

import java.math.BigInteger;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Hashtable;

public class Unicorn
        implements UnicornConst, Arm64Const, ArmConst, M68kConst, MipsConst,
        PpcConst, RiscvConst, S390xConst, SparcConst, TriCoreConst, X86Const {

    private long nativePtr;
    private int arch;
    private int mode;
    private Hashtable<Long, HookWrapper> hooks = new Hashtable<>();

    /** Wrapper around a registered hook */
    private static class HookWrapper {
        private long nativePtr;

        @Override
        protected void finalize() {
            _hookwrapper_free(nativePtr);
        }
    }

    public static class Context {
        long nativePtr;
        public int arch;
        public int mode;

        @Override
        protected void finalize() {
            _context_free(nativePtr);
        }

        /**
        * Read register value. See {@link Unicorn#reg_read(int)}.
        *
        * @param regid Register ID that is to be retrieved. This function only supports
        *        integer registers at most 64 bits long.
        * @return value of the register.
        */
        public long reg_read(int regid) throws UnicornException {
            return do_reg_read_long(nativePtr, 1, arch, regid);
        }

        /**
         * Read register value. See {@link Unicorn#reg_read(int, Object)}.
         * 
         * @param regid Register ID that is to be retrieved.
         * @param opt Options for this register, or null if no options are required.
         * @return value of the register - Long, BigInteger, or structure.
         */
        public Object reg_read(int regid, Object opt) throws UnicornException {
            return do_reg_read_obj(nativePtr, 1, arch, regid, opt);
        }

        /**
        * Write to register. See {@link Unicorn#reg_write(int, long)}.
        *
        * @param regid Register ID that is to be modified.
        * @param value Object containing the new register value.
        */
        public void reg_write(int regid, long value) throws UnicornException {
            do_reg_write_long(nativePtr, 1, arch, regid, value);
        }

        /**
        * Write to register. See {@link Unicorn#reg_write(int, Object)}.
        *
        * @param regid Register ID that is to be modified.
        * @param value Object containing the new register value.
        */
        public void reg_write(int regid, Object value) throws UnicornException {
            do_reg_write_obj(nativePtr, 1, arch, regid, value);
        }
    }

    static {
        // load libunicorn_java.{so,dylib} or unicorn_java.dll
        System.loadLibrary("unicorn_java");
    }

    /**
    * Create a new Unicorn object
    *
    * @param arch Architecture type (UC_ARCH_*)
    * @param mode Hardware mode. This is combined of UC_MODE_*
    * @see unicorn.UnicornConst
    *
    */
    public Unicorn(int arch, int mode) throws UnicornException {
        // remember these in case we need arch specific code
        this.arch = arch;
        this.mode = mode;
        nativePtr = _open(arch, mode);
    }

    /**
    * Close the underlying uc_engine* eng associated with this Unicorn object
    *
    */

    public void close() throws UnicornException {
        if (nativePtr != 0) {
            _close(nativePtr);
            nativePtr = 0;
        }
    }

    /**
    * Perform native cleanup tasks associated with a Unicorn object
    *
    */
    @Override
    protected void finalize() {
        close();
    }

    /**
    * Return combined API version & major and minor version numbers.
    *
    * @return hexadecimal number as (major << 8 | minor), which encodes both major
    *         & minor versions.
    *
    *         For example Unicorn version 1.2 would yield 0x0102
    */
    public static int version() {
        return _version();
    }

    /**
    * Determine if the given architecture is supported by this library.
    *
    * @param arch Architecture type (UC_ARCH_*)
    * @return true if this library supports the given arch.
    * @see unicorn.UnicornConst
    */
    public static boolean arch_supported(int arch) {
        return _arch_supported(arch);
    }

    /**
    * Emulate machine code in a specific duration of time.
    *
    * @param begin   Address where emulation starts
    * @param until   Address where emulation stops (i.e when this address is hit)
    * @param timeout Duration to emulate the code (in microseconds). When this
    *                value is 0, we will emulate the code in infinite time, until
    *                the code is finished.
    * @param count   The number of instructions to be emulated. When this value is
    *                0, we will emulate all the code available, until the code is
    *                finished.
    */
    public void emu_start(long begin, long until, long timeout,
            long count)
            throws UnicornException {
        _emu_start(nativePtr, begin, until, timeout, count);
    }

    /**
    * Stop emulation (which was started by emu_start() ).
    * This is typically called from callback functions registered via tracing APIs.
    * NOTE: for now, this will stop the execution only after the current block.
    */
    public void emu_stop() throws UnicornException {
        _emu_stop(nativePtr);
    }

    private static boolean is_long_register(int arch, int regid) {
        switch (arch) {
        case UC_ARCH_X86:
            return !(regid == UC_X86_REG_IDTR || regid == UC_X86_REG_GDTR ||
                regid == UC_X86_REG_LDTR || regid == UC_X86_REG_TR ||
                (regid >= UC_X86_REG_FP0 && regid <= UC_X86_REG_FP7) ||
                (regid >= UC_X86_REG_ST0 && regid <= UC_X86_REG_ST7) ||
                (regid >= UC_X86_REG_XMM0 && regid <= UC_X86_REG_XMM31) ||
                (regid >= UC_X86_REG_YMM0 && regid <= UC_X86_REG_YMM31) ||
                (regid >= UC_X86_REG_ZMM0 && regid <= UC_X86_REG_ZMM31) ||
                regid == UC_X86_REG_MSR);
        case UC_ARCH_ARM:
            return !(regid == UC_ARM_REG_CP_REG);
        case UC_ARCH_ARM64:
            return !(regid == UC_ARM64_REG_CP_REG ||
                (regid >= UC_ARM64_REG_Q0 && regid <= UC_ARM64_REG_Q31) ||
                (regid >= UC_ARM64_REG_V0 && regid <= UC_ARM64_REG_V31));
        }
        return true;
    }

    private static long do_reg_read_long(long ptr, int isContext, int arch,
            int regid) throws UnicornException {
        if (is_long_register(arch, regid)) {
            return _reg_read_long(ptr, isContext, regid);
        } else {
            throw new UnicornException("Invalid register for reg_read_long");
        }
    }

    private static Object do_reg_read_obj(long ptr, int isContext, int arch,
            int regid,
            Object opt) throws UnicornException {
        switch (arch) {
        case UC_ARCH_X86:
            if (regid == UC_X86_REG_IDTR || regid == UC_X86_REG_GDTR ||
                regid == UC_X86_REG_LDTR || regid == UC_X86_REG_TR) {
                return _reg_read_x86_mmr(ptr, isContext, regid);
            } else if ((regid >= UC_X86_REG_FP0 && regid <= UC_X86_REG_FP7) ||
                (regid >= UC_X86_REG_ST0 && regid <= UC_X86_REG_ST7)) {
                ByteBuffer b =
                    ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
                _reg_read_bytes(ptr, isContext, regid, b.array());
                return new X86_Float80(b.getLong(0), b.getShort(8));
            } else if (regid >= UC_X86_REG_XMM0 && regid <= UC_X86_REG_XMM31) {
                return do_reg_read_bigint(ptr, isContext, regid, 128);
            } else if (regid >= UC_X86_REG_YMM0 && regid <= UC_X86_REG_YMM31) {
                return do_reg_read_bigint(ptr, isContext, regid, 256);
            } else if (regid >= UC_X86_REG_ZMM0 && regid <= UC_X86_REG_ZMM31) {
                return do_reg_read_bigint(ptr, isContext, regid, 512);
            } else if (regid == UC_X86_REG_MSR) {
                X86_MSR reg = (X86_MSR) opt;
                return (Long) _reg_read_x86_msr(ptr, isContext, reg.rid);
            }
        case UC_ARCH_ARM:
            if (regid == UC_ARM_REG_CP_REG) {
                Arm_CP reg = (Arm_CP) opt;
                return (Long) _reg_read_arm_cp(ptr, isContext, reg.cp, reg.is64,
                    reg.sec, reg.crn, reg.crm, reg.opc1, reg.opc2);
            }
        case UC_ARCH_ARM64:
            if (regid == UC_ARM64_REG_CP_REG) {
                Arm64_CP reg = (Arm64_CP) opt;
                return (Long) _reg_read_arm64_cp(ptr, isContext, reg.crn,
                    reg.crm, reg.op0, reg.op1, reg.op2);
            } else if ((regid >= UC_ARM64_REG_Q0 &&
                regid <= UC_ARM64_REG_Q31) ||
                (regid >= UC_ARM64_REG_V0 && regid <= UC_ARM64_REG_V31)) {
                return do_reg_read_bigint(ptr, isContext, regid, 128);
            }
        }
        return _reg_read_long(ptr, isContext, regid);
    }

    private static void do_reg_write_long(long ptr, int isContext, int arch,
            int regid, long value) throws UnicornException {
        if (is_long_register(arch, regid)) {
            _reg_write_long(ptr, isContext, regid, value);
        } else {
            throw new UnicornException("Invalid register for reg_read_long");
        }
    }

    private static void do_reg_write_obj(long ptr, int isContext, int arch,
            int regid,
            Object value) throws UnicornException {
        switch (arch) {
        case UC_ARCH_X86:
            if (regid == UC_X86_REG_IDTR || regid == UC_X86_REG_GDTR ||
                regid == UC_X86_REG_LDTR || regid == UC_X86_REG_TR) {
                X86_MMR reg = (X86_MMR) value;
                _reg_write_x86_mmr(ptr, isContext, regid, reg.selector,
                    reg.base, reg.limit, reg.flags);
                return;
            } else if ((regid >= UC_X86_REG_FP0 && regid <= UC_X86_REG_FP7) ||
                (regid >= UC_X86_REG_ST0 && regid <= UC_X86_REG_ST7)) {
                X86_Float80 reg = (X86_Float80) value;
                ByteBuffer b =
                    ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
                b.putLong(0, reg.mantissa);
                b.putShort(8, reg.exponent);
                _reg_write_bytes(ptr, isContext, regid, b.array());
                return;
            } else if (regid >= UC_X86_REG_XMM0 && regid <= UC_X86_REG_XMM31) {
                do_reg_write_bigint(ptr, isContext, regid, (BigInteger) value,
                    128);
                return;
            } else if (regid >= UC_X86_REG_YMM0 && regid <= UC_X86_REG_YMM31) {
                do_reg_write_bigint(ptr, isContext, regid, (BigInteger) value,
                    256);
                return;
            } else if (regid >= UC_X86_REG_ZMM0 && regid <= UC_X86_REG_ZMM31) {
                do_reg_write_bigint(ptr, isContext, regid, (BigInteger) value,
                    512);
                return;
            } else if (regid == UC_X86_REG_MSR) {
                X86_MSR reg = (X86_MSR) value;
                _reg_write_x86_msr(ptr, isContext, reg.rid, reg.value);
                return;
            }
        case UC_ARCH_ARM:
            if (regid == UC_ARM_REG_CP_REG) {
                Arm_CP reg = (Arm_CP) value;
                _reg_write_arm_cp(ptr, isContext, reg.cp, reg.is64, reg.sec,
                    reg.crn, reg.crm, reg.opc1, reg.opc2, reg.val);
                return;
            }
        case UC_ARCH_ARM64:
            if (regid == UC_ARM64_REG_CP_REG) {
                Arm64_CP reg = (Arm64_CP) value;
                _reg_write_arm64_cp(ptr, isContext, reg.crn, reg.crm, reg.op0,
                    reg.op1, reg.op2, reg.val);
                return;
            } else if ((regid >= UC_ARM64_REG_Q0 &&
                regid <= UC_ARM64_REG_Q31) ||
                (regid >= UC_ARM64_REG_V0 && regid <= UC_ARM64_REG_V31)) {
                do_reg_write_bigint(ptr, isContext, regid, (BigInteger) value,
                    128);
                return;
            }
        }
        _reg_write_long(ptr, isContext, regid, (Long) value);
    }

    private static BigInteger do_reg_read_bigint(long ptr, int isContext,
            int regid,
            int nbits) {

        byte[] buf = new byte[nbits >> 3];
        _reg_read_bytes(ptr, isContext, regid, buf);
        if (ByteOrder.nativeOrder().equals(ByteOrder.LITTLE_ENDIAN)) {
            // reverse native buffer to big-endian on little-endian hosts
            int i = buf.length - 1;
            int j = 0;
            while (i > j) {
                byte temp = buf[i];
                buf[i] = buf[j];
                buf[j] = temp;
                i--;
                j++;
            }
        }
        return new BigInteger(buf);
    }

    private static void do_reg_write_bigint(long ptr, int isContext, int regid,
            BigInteger value, int nbits) {
        byte[] val = value.toByteArray();
        if (val.length > (nbits >> 3)) {
            throw new IllegalArgumentException(
                "input integer is too large for a " + nbits +
                    "-bit register (got " + (val.length * 8) + " bits)");
        }
        byte[] buf = new byte[nbits >> 3];
        if (val[0] < 0) {
            Arrays.fill(buf, (byte) 0xff);
        }

        if (ByteOrder.nativeOrder().equals(ByteOrder.LITTLE_ENDIAN)) {
            for (int i = 0; i < val.length; i++) {
                buf[i] = val[val.length - i - 1];
            }
        } else {
            System.arraycopy(val, 0, buf, buf.length - val.length, val.length);
        }
        _reg_write_bytes(ptr, isContext, regid, buf);
    }

    /**
    * Read register value. This reads any register that would return a Long
    * from {@link #reg_read(int, Object)}.
    *
    * @param regid Register ID that is to be retrieved. This function only supports
    *        integer registers at most 64 bits long.
    * @return value of the register.
    */
    public long reg_read(int regid) throws UnicornException {
        return do_reg_read_long(nativePtr, 0, arch, regid);
    }

    /**
     * Read register value. The return type depends on regid as follows.
     * opt should be null unless otherwise specified.
     * <ul>
     *  <li>{@code UC_X86_REG_*TR} => {@link X86_MMR}
     *  <li>{@code UC_X86_REG_FP*} => {@link X86_Float80}
     *  <li>{@code UC_X86_REG_ST*} => {@link X86_Float80}
     *  <li>{@code UC_X86_REG_XMM*} => {@link BigInteger} (128 bits)
     *  <li>{@code UC_X86_REG_YMM*} => {@link BigInteger} (256 bits)
     *  <li>{@code UC_X86_REG_MSR} (opt: {@link X86_MSR}) => {@link Long}
     *  <li>{@code UC_ARM_REG_CP} (opt: {@link Arm_CP}) => {@link Long}
     *  <li>{@code UC_ARM64_REG_CP} (opt: {@link Arm64_CP}) => {@link Long}
     *  <li>{@code UC_ARM64_REG_Q*} => {@link BigInteger} (128 bits)
     *  <li>{@code UC_ARM64_REG_V*} => {@link BigInteger} (128 bits)
     * </ul>
     * 
     * @param regid Register ID that is to be retrieved.
     * @param opt Options for this register, or null if no options are required.
     * @return value of the register - Long, BigInteger, or structure.
     */
    public Object reg_read(int regid, Object opt) throws UnicornException {
        return do_reg_read_obj(nativePtr, 0, arch, regid, opt);
    }

    /**
    * Write to register. This sets any register that doesn't require special
    * options and which is at most 64 bits long.
    *
    * @param regid Register ID that is to be modified.
    * @param value Object containing the new register value.
    */
    public void reg_write(int regid, long value) throws UnicornException {
        do_reg_write_long(nativePtr, 0, arch, regid, value);
    }

    /**
    * Write to register. The type of {@code value} depends on regid:
    * <ul>
    *  <li>{@code UC_X86_REG_*TR} => {@link X86_MMR}
    *  <li>{@code UC_X86_REG_FP*} => {@link X86_Float80}
    *  <li>{@code UC_X86_REG_ST*} => {@link X86_Float80}
    *  <li>{@code UC_X86_REG_XMM*} => {@link BigInteger} (128 bits)
    *  <li>{@code UC_X86_REG_YMM*} => {@link BigInteger} (256 bits)
    *  <li>{@code UC_X86_REG_MSR} => {@link X86_MSR}
    *  <li>{@code UC_ARM_REG_CP}  => {@link Arm_CP}
    *  <li>{@code UC_ARM64_REG_CP} => {@link Arm64_CP}
    *  <li>{@code UC_ARM64_REG_Q*} => {@link BigInteger} (128 bits)
    *  <li>{@code UC_ARM64_REG_V*} => {@link BigInteger} (128 bits)
    * </ul>
    *
    * @param regid Register ID that is to be modified.
    * @param value Object containing the new register value.
    */
    public void reg_write(int regid, Object value) throws UnicornException {
        do_reg_write_obj(nativePtr, 0, arch, regid, value);
    }

    /**
    * Read from memory.
    *
    * @param address Start address of the memory region to be read.
    * @param size    Number of bytes to be retrieved.
    * @return Byte array containing the contents of the requested memory range.
    */
    public byte[] mem_read(long address, int size) throws UnicornException {
        byte[] result = new byte[size];
        _mem_read(nativePtr, address, result);
        return result;
    }

    /**
    * Write to memory.
    *
    * @param address Start addres of the memory region to be written.
    * @param bytes   The values to be written into memory. bytes.length bytes will
    *                be written.
    */
    public void mem_write(long address, byte[] bytes) throws UnicornException {
        _mem_write(nativePtr, address, bytes);
    }

    /**
    * Query internal status of engine.
    *
    * @param type   query type. See UC_QUERY_*
    * @param result save the internal status queried
    *
    * @return: error code. see UC_ERR_*
    * @see unicorn.UnicornConst
    */
    public long query(int type) throws UnicornException {
        return _query(nativePtr, type);
    }

    /**
    * Report the last error number when some API function fail.
    * Like glibc's errno, uc_errno might not retain its old value once accessed.
    *
    * @return Error code of uc_err enum type (UC_ERR_*, see above)
    * @see unicorn.UnicornConst
    */
    public int errno() {
        return _errno(nativePtr);
    }

    /**
    * Return a string describing given error code.
    *
    * @param code Error code (see UC_ERR_* above)
    * @return Returns a String that describes the error code
    * @see unicorn.UnicornConst
    */
    public static String strerror(int code) {
        return _strerror(code);
    }

    public int ctl_get_mode() {
        return _ctl_get_mode(nativePtr);
    }

    public int ctl_get_arch() {
        return _ctl_get_arch(nativePtr);
    }

    public long ctl_get_timeout() {
        return _ctl_get_timeout(nativePtr);
    }

    public int ctl_get_page_size() {
        return _ctl_get_page_size(nativePtr);
    }

    public void ctl_set_page_size(int page_size) {
        _ctl_set_page_size(nativePtr, page_size);
    }

    public void ctl_exits_enabled(boolean value) {
        _ctl_set_use_exits(nativePtr, value);
    }

    public long ctl_get_exits_cnt() {
        return _ctl_get_exits_cnt(nativePtr);
    }

    public long[] ctl_get_exits() {
        return _ctl_get_exits(nativePtr);
    }

    public void ctl_set_exits(long[] exits) {
        _ctl_set_exits(nativePtr, exits);
    }

    public int ctl_get_cpu_model() {
        return _ctl_get_cpu_model(nativePtr);
    }

    /**
    * Set the emulated cpu model.
    *
    * @param cpu_model CPU model type (see UC_CPU_*).
    */
    public void ctl_set_cpu_model(int cpu_model) {
        _ctl_set_cpu_model(nativePtr, cpu_model);
    }

    public TranslationBlock ctl_request_cache(long address) {
        return _ctl_request_cache(nativePtr, address);
    }

    public void ctl_remove_cache(long address, long end) {
        _ctl_remove_cache(nativePtr, address, end);
    }

    public void ctl_flush_tb() {
        _ctl_flush_tb(nativePtr);
    }

    public void ctl_flush_tlb() {
        _ctl_flush_tlb(nativePtr);
    }

    public void ctl_tlb_mode(int mode) {
        _ctl_tlb_mode(nativePtr, mode);
    }

    private long registerHook(long val) {
        HookWrapper wrapper = new HookWrapper();
        wrapper.nativePtr = val;
        hooks.put(val, wrapper);
        return val;
    }

    /**
    * Register a UC_HOOK_INTR hook. The registered callback function will be
    * invoked whenever an interrupt instruction is executed.
    *
    * @param callback  Implementation of a InterruptHook interface
    * @param user_data User data to be passed to the callback function each time
    *                  the event is triggered
    */
    public long hook_add(InterruptHook callback, Object user_data)
            throws UnicornException {
        return registerHook(
            _hook_add(nativePtr, UC_HOOK_INTR, callback, user_data, 1, 0));
    }

    /**
    * Register a UC_HOOK_INSN hook. The registered callback function will be
    * invoked whenever the matching special instruction is executed.
    * The exact interface called will depend on the instruction being hooked.
    *
    * @param callback  Implementation of an InstructionHook sub-interface
    * @param insn      UC_<ARCH>_INS_<INSN> constant, e.g. UC_X86_INS_IN or UC_ARM64_INS_MRS
    * @param begin     Start address of hooking range
    * @param end       End address of hooking range
    * @param user_data User data to be passed to the callback function each time
    *                  the event is triggered
    */
    public long hook_add(InstructionHook callback, int insn, long begin,
            long end,
            Object user_data)
            throws UnicornException {
        return registerHook(_hook_add(nativePtr, UC_HOOK_INSN, callback,
            user_data, begin, end, insn));
    }

    /**
    * Register a UC_HOOK_CODE hook. The registered callback function will be
    * invoked when an instruction is executed from the address range
    * begin <= PC <= end. For the special case in which begin > end, the
    * callback will be invoked for ALL instructions.
    *
    * @param callback  Implementation of a CodeHook interface
    * @param begin     Start address of hooking range
    * @param end       End address of hooking range
    * @param user_data User data to be passed to the callback function each time
    *                  the event is triggered
    */
    public long hook_add(CodeHook callback, long begin, long end,
            Object user_data)
            throws UnicornException {
        return registerHook(_hook_add(nativePtr, UC_HOOK_CODE, callback,
            user_data, begin, end));
    }

    /**
    * Register a UC_HOOK_BLOCK hook. The registered callback function will be
    * invoked when a basic block is entered and the address of the basic block
    * (BB) falls in the range begin <= BB <= end. For the special case in which
    * begin > end, the callback will be invoked whenver any basic block is
    * entered.
    *
    * @param callback  Implementation of a BlockHook interface
    * @param begin     Start address of hooking range
    * @param end       End address of hooking range
    * @param user_data User data to be passed to the callback function each time
    *                  the event is triggered
    */
    public long hook_add(BlockHook callback, long begin, long end,
            Object user_data)
            throws UnicornException {
        return registerHook(_hook_add(nativePtr, UC_HOOK_BLOCK, callback,
            user_data, begin, end));
    }

    /**
    * Register a UC_HOOK_MEM_VALID hook (UC_HOOK_MEM_{READ,WRITE_FETCH} and/or
    * UC_HOOK_MEM_READ_AFTER. The registered callback function will be
    * invoked whenever a corresponding memory operation is performed within the
    * address range begin <= addr <= end. For the special case in which
    * begin > end, the callback will be invoked for ALL memory operations.
    *
    * @param callback  Implementation of a MemHook interface
    * @param type      UC_HOOK_MEM_* constant for a valid memory event
    * @param begin     Start address of memory range
    * @param end       End address of memory range
    * @param user_data User data to be passed to the callback function each time
    *                  the event is triggered
    */
    public long hook_add(MemHook callback, int type, long begin, long end,
            Object user_data)
            throws UnicornException {
        return registerHook(
            _hook_add(nativePtr, type, callback, user_data, begin, end));
    }

    /**
    * Register a UC_HOOK_MEM_XXX_UNMAPPED and/or UC_HOOK_MEM_XXX_PROT hook.
    * The registered callback function will be invoked whenever a memory
    * operation is attempted from an invalid or protected memory address.
    * The registered callback function will be invoked whenever a
    * corresponding memory operation is performed within the  address range
    * begin <= addr <= end. For the special case in which begin > end, the
    * callback will be invoked for ALL memory operations.
    *
    * @param callback  Implementation of a EventMemHook interface
    * @param type      Type of memory event being hooked such as
    *                  UC_HOOK_MEM_READ_UNMAPPED or UC_HOOK_MEM_WRITE_PROT
    * @param begin     Start address of memory range
    * @param end       End address of memory range
    * @param user_data User data to be passed to the callback function each time
    *                  the event is triggered
    */
    public long hook_add(EventMemHook callback, int type, long begin, long end,
            Object user_data)
            throws UnicornException {
        return registerHook(
            _hook_add(nativePtr, type, callback, user_data, begin, end));
    }

    public long hook_add(InvalidInstructionHook callback,
            Object user_data) {
        return registerHook(_hook_add(nativePtr, UC_HOOK_INSN_INVALID, callback,
            user_data, 1, 0));
    }

    public long hook_add(EdgeGeneratedHook callback, long begin, long end,
            Object user_data)
            throws UnicornException {
        return registerHook(_hook_add(nativePtr, UC_HOOK_EDGE_GENERATED,
            callback, user_data, begin, end));
    }

    public long hook_add(TcgOpcodeHook callback, long begin, long end,
            int opcode, int flags,
            Object user_data)
            throws UnicornException {
        return registerHook(_hook_add(nativePtr, UC_HOOK_TCG_OPCODE, callback,
            user_data, begin, end, opcode, flags));
    }

    public long hook_add(TlbFillHook callback, long begin, long end,
            Object user_data) throws UnicornException {
        return registerHook(_hook_add(nativePtr, UC_HOOK_TLB_FILL, callback,
            user_data, begin, end));
    }

    /** Remove a hook that was previously registered.
     * 
     * @param hook The return value from any hook_add function.
     */
    public void hook_del(long hook) throws UnicornException {
        if (hooks.contains(hook)) {
            hooks.remove(hooks, hook);
            _hook_del(nativePtr, hook);
        } else {
            throw new UnicornException("Hook is not registered!");
        }
    }

    /**
     * Create a memory-mapped I/O range.
     */
    public void mmio_map(long address, long size, MmioReadHandler read_cb,
            Object user_data_read, MmioWriteHandler write_cb,
            Object user_data_write)
            throws UnicornException {
        /* TODO: Watch mem_unmap to know when it's safe to release the hook. */
        long[] hooks = _mmio_map(nativePtr, address, size, read_cb,
            user_data_read, write_cb, user_data_write);
        for (long hook : hooks) {
            registerHook(hook);
        }
    }

    /**
    * Map a range of memory.
    *
    * @param address Base address of the memory range
    * @param size    Size of the memory block.
    * @param perms   Permissions on the memory block. A combination of
    *                UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
    */
    public void mem_map(long address, long size, int perms)
            throws UnicornException {
        _mem_map(nativePtr, address, size, perms);
    }

    /**
    * Map existing host memory in for emulation.
    * This API adds a memory region that can be used by emulation.
    *
    * @param address Base address of the memory range
    * @param buf     Direct-mapped Buffer referencing the memory to
    *                map into the emulator. IMPORTANT: You are responsible
    *                for ensuring that this Buffer remains alive as long
    *                as the emulator is running!
    * @param perms   Permissions on the memory block. A combination of
    *                UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
    */
    public void mem_map_ptr(long address, Buffer buf, int perms)
            throws UnicornException {
        _mem_map_ptr(nativePtr, address, buf, perms);
    }

    /**
    * Unmap a range of memory.
    *
    * @param address Base address of the memory range
    * @param size    Size of the memory block.
    */
    public void mem_unmap(long address, long size) throws UnicornException {
        _mem_unmap(nativePtr, address, size);
    }

    /**
    * Change permissions on a range of memory.
    *
    * @param address Base address of the memory range
    * @param size    Size of the memory block.
    * @param perms   New permissions on the memory block. A combination of
    *                UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
    */
    public void mem_protect(long address, long size, int perms)
            throws UnicornException {
        _mem_protect(nativePtr, address, size, perms);
    }

    /**
    * Retrieve all memory regions mapped by mem_map() and mem_map_ptr()
    * NOTE: memory regions may be split by mem_unmap()
    *
    * @return list of mapped regions.
    */
    public MemRegion[] mem_regions() throws UnicornException {
        return _mem_regions(nativePtr);
    }

    public Context context_save() throws UnicornException {
        long ptr = _context_alloc(nativePtr);
        Context context = new Context();
        context.nativePtr = ptr;
        context.arch = arch;
        context.mode = mode;
        _context_save(nativePtr, ptr);
        return context;
    }

    public void context_update(Context context) throws UnicornException {
        if (context.arch != arch || context.mode != mode) {
            throw new UnicornException(
                "Context is not compatible with this Unicorn");
        }
        _context_save(nativePtr, context.nativePtr);
    }

    public void context_restore(Context context) throws UnicornException {
        if (context.arch != arch || context.mode != mode) {
            throw new UnicornException(
                "Context is not compatible with this Unicorn");
        }
        _context_restore(nativePtr, context.nativePtr);
    }

    /* Native implementation */
    private static native long _open(int arch, int mode)
            throws UnicornException;

    private static native void _close(long uc) throws UnicornException;

    private static native void _emu_start(long uc, long begin, long until,
            long timeout,
            long count) throws UnicornException;

    private static native void _emu_stop(long uc) throws UnicornException;

    private static native long _reg_read_long(long ptr, int isContext,
            int regid) throws UnicornException;

    private static native void _reg_read_bytes(long ptr, int isContext,
            int regid, byte[] data) throws UnicornException;

    private static native void _reg_write_long(long ptr, int isContext,
            int regid, long val)
            throws UnicornException;

    private static native void _reg_write_bytes(long ptr, int isContext,
            int regid, byte[] data) throws UnicornException;

    private static native X86_MMR _reg_read_x86_mmr(long ptr, int isContext,
            int regid) throws UnicornException;

    private static native void _reg_write_x86_mmr(long ptr, int isContext,
            int regid, short selector, long base, int limit, int flags)
            throws UnicornException;

    private static native long _reg_read_x86_msr(long ptr, int isContext,
            int rid) throws UnicornException;

    private static native void _reg_write_x86_msr(long ptr, int isContext,
            int rid, long value) throws UnicornException;

    private static native long _reg_read_arm_cp(long ptr, int isContext, int cp,
            int is64, int sec, int crn, int crm, int opc1, int opc2)
            throws UnicornException;

    private static native void _reg_write_arm_cp(long ptr, int isContext,
            int cp, int is64, int sec, int crn, int crm, int opc1, int opc2,
            long value) throws UnicornException;

    private static native long _reg_read_arm64_cp(long ptr, int isContext,
            int crn, int crm, int op0, int op1, int op2)
            throws UnicornException;

    private static native void _reg_write_arm64_cp(long ptr, int isContext,
            int crn, int crm, int op0, int op1, int op2, long value)
            throws UnicornException;

    private static native void _mem_read(long uc, long address,
            byte[] dest) throws UnicornException;

    private static native void _mem_write(long uc, long address,
            byte[] src) throws UnicornException;

    private static native int _version();

    private static native boolean _arch_supported(int arch);

    private static native long _query(long uc, int type)
            throws UnicornException;

    private static native int _errno(long uc);

    private static native String _strerror(int code);

    private native long _hook_add(long uc, int type, Hook callback,
            Object user_data, long begin, long end) throws UnicornException;

    private native long _hook_add(long uc, int type, Hook callback,
            Object user_data, long begin, long end, int arg)
            throws UnicornException;

    private native long _hook_add(long uc, int type, Hook callback,
            Object user_data, long begin, long end, int arg1, int arg2)
            throws UnicornException;

    private static native void _hook_del(long uc, long hh)
            throws UnicornException;

    private static native void _hookwrapper_free(long hh)
            throws UnicornException;

    private native long[] _mmio_map(long uc, long address, long size,
            MmioReadHandler read_cb, Object user_data_read,
            MmioWriteHandler write_cb, Object user_data_write)
            throws UnicornException;

    private static native void _mem_map(long uc, long address, long size,
            int perms) throws UnicornException;

    private static native void _mem_map_ptr(long uc, long address, Buffer buf,
            int perms) throws UnicornException;

    private static native void _mem_unmap(long uc, long address, long size)
            throws UnicornException;

    private static native void _mem_protect(long uc, long address, long size,
            int perms) throws UnicornException;

    private static native MemRegion[] _mem_regions(long uc)
            throws UnicornException;

    private static native long _context_alloc(long uc) throws UnicornException;

    private static native void _context_free(long ctx) throws UnicornException;

    private static native void _context_save(long uc, long ctx)
            throws UnicornException;

    private static native void _context_restore(long uc, long ctx)
            throws UnicornException;

    private static native int _ctl_get_mode(long uc) throws UnicornException;

    private static native int _ctl_get_arch(long uc) throws UnicornException;

    private static native long _ctl_get_timeout(long uc)
            throws UnicornException;

    private static native int _ctl_get_page_size(long uc)
            throws UnicornException;

    private static native void _ctl_set_page_size(long uc, int page_size)
            throws UnicornException;

    private static native void _ctl_set_use_exits(long uc, boolean value)
            throws UnicornException;

    private static native long _ctl_get_exits_cnt(long uc)
            throws UnicornException;

    private static native long[] _ctl_get_exits(long uc)
            throws UnicornException;

    private static native void _ctl_set_exits(long uc, long[] exits)
            throws UnicornException;

    private static native int _ctl_get_cpu_model(long uc)
            throws UnicornException;

    private static native void _ctl_set_cpu_model(long uc, int cpu_model)
            throws UnicornException;

    private static native TranslationBlock _ctl_request_cache(long uc,
            long address) throws UnicornException;

    private static native void _ctl_remove_cache(long uc, long address,
            long end) throws UnicornException;

    private static native void _ctl_flush_tb(long uc) throws UnicornException;

    private static native void _ctl_flush_tlb(long uc) throws UnicornException;

    private static native void _ctl_tlb_mode(long uc, int mode)
            throws UnicornException;

}
