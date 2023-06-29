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
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/** Unicorn is a lightweight multi-platform, multi-architecture CPU emulator framework. */
public class Unicorn
        implements UnicornConst, Arm64Const, ArmConst, M68kConst, MipsConst,
        PpcConst, RiscvConst, S390xConst, SparcConst, TriCoreConst, X86Const {

    private long nativePtr;
    private int arch;
    private int mode;
    private Hashtable<Long, HookWrapper> hooks = new Hashtable<>();

    /** Instead of handing out native pointers, we'll hand out a handle
     * ID for safety. This prevents things like "double frees" - 
     * accidentally releasing an unrelated object via handle reuse. */
    private static AtomicLong allocCounter = new AtomicLong(0x1000);

    private static long nextAllocCounter() {
        return allocCounter.addAndGet(8);
    }

    /** Wrapper around a registered hook */
    private static class HookWrapper {
        Hook hook;
        long nativePtr;

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
         * Read register value from saved context.
         *
         * @param regid Register ID that is to be retrieved. This function only supports
         *        integer registers at most 64 bits long.
         * @return value of the register.
         * @see Unicorn#reg_read(int)
         */
        public long reg_read(int regid) throws UnicornException {
            return do_reg_read_long(nativePtr, 1, arch, regid);
        }

        /**
         * Read register value from saved context.
         * 
         * @param regid Register ID that is to be retrieved.
         * @param opt Options for this register, or null if no options are required.
         * @return value of the register - Long, BigInteger, or structure.
         * @see Unicorn#reg_read(int, Object)
         */
        public Object reg_read(int regid, Object opt) throws UnicornException {
            return do_reg_read_obj(nativePtr, 1, arch, regid, opt);
        }

        /**
         * Write to register in saved context.
         *
         * @param regid Register ID that is to be modified.
         * @param value Object containing the new register value.
         * @see Unicorn#reg_write(int, long)
         */
        public void reg_write(int regid, long value) throws UnicornException {
            do_reg_write_long(nativePtr, 1, arch, regid, value);
        }

        /**
         * Write to register in saved context.
         *
         * @param regid Register ID that is to be modified.
         * @param value Object containing the new register value.
         * @see Unicorn#reg_write(int, Object)
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
     * @param arch Architecture type. One of the {@code UC_ARCH_*} constants.
     * @param mode Hardware mode. Bitwise combination of {@code UC_MODE_*} constants.
     * @see UnicornConst
     *
     */
    public Unicorn(int arch, int mode) throws UnicornException {
        // remember these in case we need arch specific code
        this.arch = arch;
        this.mode = mode;
        nativePtr = _open(arch, mode);
    }

    /**
     * Close the C {@code uc_engine} associated with this Unicorn object,
     * freeing all associated resources. After calling this method, the
     * API will no longer be usable.
     */
    public void close() throws UnicornException {
        if (nativePtr != 0) {
            _close(nativePtr);
            nativePtr = 0;
        }
    }

    /**
     * Automatically close the {@code uc_engine} upon GC finalization.
     */
    @Override
    protected void finalize() {
        close();
    }

    /**
     * Return combined API version & major and minor version numbers.
     *
     * @return version number as {@code (major << 24 | minor << 16 |
     *         patch << 8 | extra)}.
     *         For example, Unicorn version 2.0.1 final would be 0x020001ff.
     */
    public static int version() {
        return _version();
    }

    /**
     * Determine if the given architecture is supported by this library.
     *
     * @param arch Architecture type ({@code UC_ARCH_*} constant)
     * @return {@code true} if this library supports the given arch.
     * @see UnicornConst
     */
    public static boolean arch_supported(int arch) {
        return _arch_supported(arch);
    }

    /**
     * Emulate machine code for a specific length of time or number of
     * instructions.
     *
     * @param begin   Address where emulation starts
     * @param until   Address where emulation stops (i.e. when this address is hit)
     * @param timeout Duration to emulate the code for, in microseconds, or 0 to
     *                run indefinitely.
     * @param count   The maximum number of instructions to execute, or 0 to
     *                execute indefinitely.
     * @throws UnicornException if an unhandled CPU exception or other error
     *                occurs during emulation.
     */
    public void emu_start(long begin, long until, long timeout,
            long count)
            throws UnicornException {
        _emu_start(nativePtr, begin, until, timeout, count);
    }

    /**
     * Stop emulation (which was started by {@link #emu_start()}).
     *
     * This can be called from hook callbacks or from a separate thread.
     * NOTE: for now, this will stop the execution only after the current
     * basic block.
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
            break;
        case UC_ARCH_ARM:
            if (regid == UC_ARM_REG_CP_REG) {
                Arm_CP reg = (Arm_CP) opt;
                return (Long) _reg_read_arm_cp(ptr, isContext, reg.cp, reg.is64,
                    reg.sec, reg.crn, reg.crm, reg.opc1, reg.opc2);
            }
            break;
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
            break;
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
            break;
        case UC_ARCH_ARM:
            if (regid == UC_ARM_REG_CP_REG) {
                Arm_CP reg = (Arm_CP) value;
                _reg_write_arm_cp(ptr, isContext, reg.cp, reg.is64, reg.sec,
                    reg.crn, reg.crm, reg.opc1, reg.opc2, reg.val);
                return;
            }
            break;
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
            break;
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
        return new BigInteger(1, buf);
    }

    private static void do_reg_write_bigint(long ptr, int isContext, int regid,
            BigInteger value, int nbits) {
        byte[] val = value.toByteArray();
        byte[] buf = new byte[nbits >> 3];
        if (val.length == ((nbits >> 3) + 1) && val[0] == 0x00) {
            // unsigned value >= 2^(nbits - 1): has a zero sign bit
            val = Arrays.copyOfRange(val, 1, val.length);
        } else if (val[0] < 0) {
            Arrays.fill(buf, (byte) 0xff);
        }

        if (val.length > (nbits >> 3)) {
            throw new IllegalArgumentException(
                "input integer is too large for a " + nbits +
                    "-bit register (got " + (value.bitLength() + 1) + " bits)");
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
     * Read register value of at most 64 bits in size.
     *
     * @param regid Register ID that is to be retrieved. This function only supports
     *        integer registers at most 64 bits long.
     * @return value of the register.
     * @see {@link #reg_read(int, Object)} to read larger registers or
     *      registers requiring configuration.
     * @throws UnicornException if the register is not valid for the current
     *           architecture or mode.
     */
    public long reg_read(int regid) throws UnicornException {
        return do_reg_read_long(nativePtr, 0, arch, regid);
    }

    /**
     * Read register value. The return type depends on {@code regid} as
     * follows. {@code opt} should be {@code null} unless otherwise specified.
     * <ul>
     *  <li>{@code UC_X86_REG_*TR} => {@link X86_MMR}
     *  <li>{@code UC_X86_REG_FP*} => {@link X86_Float80}
     *  <li>{@code UC_X86_REG_ST*} => {@link X86_Float80}
     *  <li>{@code UC_X86_REG_XMM*} => {@link BigInteger} (128 bits)
     *  <li>{@code UC_X86_REG_YMM*} => {@link BigInteger} (256 bits)
     *  <li>{@code UC_X86_REG_ZMM*} => {@link BigInteger} (512 bits)
     *  <li>{@code UC_X86_REG_MSR} (opt: {@link X86_MSR}) => {@link Long}
     *  <li>{@code UC_ARM_REG_CP} (opt: {@link Arm_CP}) => {@link Long}
     *  <li>{@code UC_ARM64_REG_CP} (opt: {@link Arm64_CP}) => {@link Long}
     *  <li>{@code UC_ARM64_REG_Q*} => {@link BigInteger} (128 bits)
     *  <li>{@code UC_ARM64_REG_V*} => {@link BigInteger} (128 bits)
     * </ul>
     * 
     * {@link BigInteger} registers always produce non-negative results (i.e.
     * they read as unsigned integers).
     * 
     * @param regid Register ID that is to be retrieved.
     * @param opt Options for this register, or {@code null} if no options
     *        are required.
     * @return value of the register - {@link Long}, {@link BigInteger},
     *         or other class.
     * @throws UnicornException if the register is not valid for the current
     *           architecture or mode.
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
     * @see {@link #reg_read(int, Object)} to write larger registers or
     *      registers requiring configuration.
     * @throws UnicornException if the register is not valid for the current
     *           architecture or mode.
     */
    public void reg_write(int regid, long value) throws UnicornException {
        do_reg_write_long(nativePtr, 0, arch, regid, value);
    }

    /**
     * Write to register. The type of {@code value} depends on {@code regid}:
     * <ul>
     *  <li>{@code UC_X86_REG_*TR} => {@link X86_MMR}
     *  <li>{@code UC_X86_REG_FP*} => {@link X86_Float80}
     *  <li>{@code UC_X86_REG_ST*} => {@link X86_Float80}
     *  <li>{@code UC_X86_REG_XMM*} => {@link BigInteger} (128 bits)
     *  <li>{@code UC_X86_REG_YMM*} => {@link BigInteger} (256 bits)
     *  <li>{@code UC_X86_REG_ZMM*} => {@link BigInteger} (512 bits)
     *  <li>{@code UC_X86_REG_MSR} => {@link X86_MSR}
     *  <li>{@code UC_ARM_REG_CP}  => {@link Arm_CP}
     *  <li>{@code UC_ARM64_REG_CP} => {@link Arm64_CP}
     *  <li>{@code UC_ARM64_REG_Q*} => {@link BigInteger} (128 bits)
     *  <li>{@code UC_ARM64_REG_V*} => {@link BigInteger} (128 bits)
     * </ul>
     * 
     * {@link BigInteger} values can be signed or unsigned, as long as the
     * value fits in the target register size. Values that are too large will
     * be rejected.
     *
     * @param regid Register ID that is to be modified.
     * @param value Object containing the new register value.
     * @throws UnicornException if the register is not valid for the current
     *           architecture or mode.
     */
    public void reg_write(int regid, Object value) throws UnicornException {
        do_reg_write_obj(nativePtr, 0, arch, regid, value);
    }

    /** @deprecated Use individual calls to {@code reg_read} instead.
     * This method is deprecated as it is much slower than
     * {@link #reg_read(int)} for reading 64-bit-or-smaller registers.
     */
    @Deprecated
    public Object[] reg_read_batch(int regids[]) throws UnicornException {
        Object[] res = new Object[regids.length];
        for (int i = 0; i < regids.length; i++) {
            res[i] = reg_read(regids[i], null);
        }
        return res;
    }

    /** @deprecated Use individual calls to {@code reg_write} instead.
     * This method is deprecated as it is much slower than
     * {@link #reg_write(int, long)} for writing 64-bit-or-smaller registers.
     */
    @Deprecated
    public void reg_write_batch(int regids[], Object vals[])
            throws UnicornException {
        if (regids.length != vals.length) {
            throw new UnicornException(strerror(UC_ERR_ARG));
        }
        for (int i = 0; i < regids.length; i++) {
            reg_write(regids[i], vals[i]);
        }
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

    /** @deprecated Use {@link #mem_read(long, int)} instead. */
    @Deprecated
    public byte[] mem_read(long address, long size) throws UnicornException {
        if (size < 0) {
            throw new NegativeArraySizeException("size cannot be negative");
        } else if (size > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("size must fit in an int");
        }
        byte[] result = new byte[(int) size];
        _mem_read(nativePtr, address, result);
        return result;
    }

    /**
     * Write to memory.
     *
     * @param address Start address of the memory region to be written.
     * @param bytes   The values to be written into memory. {@code bytes.length}
     *                bytes will be written.
     */
    public void mem_write(long address, byte[] bytes) throws UnicornException {
        _mem_write(nativePtr, address, bytes);
    }

    /**
     * Query the internal status of the engine.
     *
     * @param type query type, one of the {@code UC_QUERY_*} constants.
     * @return result of the query
     * @see UnicornConst
     */
    public long query(int type) throws UnicornException {
        return _query(nativePtr, type);
    }

    /**
     * Report the last error number when some API functions fail.
     * {@code errno} may not retain its old value once accessed.
     *
     * @return Error code, one of the {@code UC_ERR_*} constants.
     * @deprecated Not actually useful in Java; error numbers are always
     * converted into {@link UnicornException} exceptions.
     * @see UnicornConst
     */
    @Deprecated
    public int errno() {
        return _errno(nativePtr);
    }

    /**
     * Return a string describing the given error code.
     *
     * @param code Error code, one of the {@code UC_ERR_*} constants.
     * @return a String that describes the error code
     * @see UnicornConst
     */
    public static String strerror(int code) {
        return _strerror(code);
    }

    /**
     * Get the current emulation mode.
     * 
     * @return a bitwise OR of {@code UC_MODE_*} constants.
     */
    public int ctl_get_mode() throws UnicornException {
        return _ctl_get_mode(nativePtr);
    }

    /**
     * Get the current emulation architecture.
     * 
     * @return a {@code UC_ARCH_*} constant.
     */
    public int ctl_get_arch() throws UnicornException {
        return _ctl_get_arch(nativePtr);
    }

    /** Get the current execution timeout, in nanoseconds. */
    public long ctl_get_timeout() throws UnicornException {
        return _ctl_get_timeout(nativePtr);
    }

    /** Get the current page size, in bytes. */
    public int ctl_get_page_size() throws UnicornException {
        return _ctl_get_page_size(nativePtr);
    }

    /** Set the current page size, in bytes.
     * 
     * @param page_size Requested page type. Must be a power of two.
     * @throws UnicornException if the architecture does not support setting
     *                          the page size.
     */
    public void ctl_set_page_size(int page_size) throws UnicornException {
        _ctl_set_page_size(nativePtr, page_size);
    }

    /** Enable or disable multiple exit support.
     *
     * Exits provide a more flexible way to terminate execution, versus using
     * the {@code until} parameter to {@link #emu_start}. When exits are
     * enabled, execution will stop at any of the configured exit addresses,
     * and the {@code until} parameter will be ignored.
     */
    public void ctl_exits_enabled(boolean value) throws UnicornException {
        _ctl_set_use_exits(nativePtr, value);
    }

    /** Get the current number of active exits.
     * 
     * @return The number of exit addresses currently configured
     * @throws UnicornException if exits are not enabled
     */
    public long ctl_get_exits_cnt() throws UnicornException {
        return _ctl_get_exits_cnt(nativePtr);
    }

    /** Get the current active exits.
     * 
     * @return An array of active exit addresses.
     * @throws UnicornException if exits are not enabled
     */
    public long[] ctl_get_exits() throws UnicornException {
        return _ctl_get_exits(nativePtr);
    }

    /** Set the active exit addresses.
     * 
     * @param exits An array of exit addresses to use.
     * @throws UnicornException if exits are not enabled
     */
    public void ctl_set_exits(long[] exits) throws UnicornException {
        _ctl_set_exits(nativePtr, exits);
    }

    /** Get the emulated CPU model.
     * 
     * @return One of the {@code UC_CPU_<ARCH>_*} constants. See the
     *         appropriate Const class for a list of valid constants.
     */
    public int ctl_get_cpu_model() throws UnicornException {
        return _ctl_get_cpu_model(nativePtr);
    }

    /** Set the emulated CPU model. Note that this option can only be called
     * immediately after constructing the Unicorn object, before any other APIs
     * are called.
     * 
     * @param cpu_model One of the {@code UC_CPU_<ARCH>_*} constants. See the
     *                  appropriate Const class for a list of valid constants.
     */
    public void ctl_set_cpu_model(int cpu_model) throws UnicornException {
        _ctl_set_cpu_model(nativePtr, cpu_model);
    }

    /** Request the TB cache at a specific address. */
    public TranslationBlock ctl_request_cache(long address)
            throws UnicornException {
        return _ctl_request_cache(nativePtr, address);
    }

    /** Invalidate the TB cache for a specific range of addresses
     * {@code [address, end)}. Note that invalidation will not include address
     * {@code end} itself.
     * 
     * @param address The first address in the region to invalidate
     * @param end     The last address in the region to invalidate, plus one
     */
    public void ctl_remove_cache(long address, long end)
            throws UnicornException {
        _ctl_remove_cache(nativePtr, address, end);
    }

    /** Flush the entire TB cache, invalidating all translation blocks. */
    public void ctl_flush_tb() throws UnicornException {
        _ctl_flush_tb(nativePtr);
    }

    /** Flush the TLB cache, invalidating all TLB cache entries and
     * translation blocks. */
    public void ctl_flush_tlb() throws UnicornException {
        _ctl_flush_tlb(nativePtr);
    }

    /** Change the TLB implementation.
     * 
     * @param mode One of the {@code UC_TLB_*} constants.
     * @see UnicornConst
     */
    public void ctl_tlb_mode(int mode) throws UnicornException {
        _ctl_tlb_mode(nativePtr, mode);
    }

    private long registerHook(Hook hook, long val) {
        HookWrapper wrapper = new HookWrapper();
        wrapper.hook = hook;
        wrapper.nativePtr = val;
        long index = nextAllocCounter();
        hooks.put(index, wrapper);
        return index;
    }

    /**
     * Register a {@code UC_HOOK_INTR} hook. The hook function will be invoked
     * whenever a CPU interrupt occurs.
     *
     * @param callback  Implementation of a {@link InterruptHook} interface
     * @param user_data User data to be passed to the callback function each
     *                  time the event is triggered
     * @return A value that can be passed to {@link #hook_del} to unregister
     *         this hook
     */
    public long hook_add(InterruptHook callback, Object user_data)
            throws UnicornException {
        return registerHook(callback,
            _hook_add(nativePtr, UC_HOOK_INTR, callback, user_data, 1, 0));
    }

    /**
     * Register a {@code UC_HOOK_INSN} hook. The hook function will be
     * invoked whenever the matching special instruction is executed.
     * The exact interface called will depend on the instruction being hooked.
     *
     * @param callback  Implementation of an {@link InstructionHook} sub-interface
     * @param insn      {@code UC_<ARCH>_INS_<INSN>} constant, e.g.
     *                  {@code UC_X86_INS_IN} or {@code UC_ARM64_INS_MRS}
     * @param begin     Start address of hooking range
     * @param end       End address of hooking range
     * @param user_data User data to be passed to the callback function each
     *                  time the event is triggered
     * @return A value that can be passed to {@link #hook_del} to unregister
     *         this hook
     */
    public long hook_add(InstructionHook callback, int insn, long begin,
            long end,
            Object user_data)
            throws UnicornException {
        return registerHook(callback, _hook_add(nativePtr, UC_HOOK_INSN,
            callback, user_data, begin, end, insn));
    }

    /**
     * Register a {@code UC_HOOK_INSN} hook for all program addresses.
     * The exact interface called will depend on the instruction being hooked.
     *
     * @param callback  Implementation of an {@link InstructionHook}
     *                  sub-interface
     * @param insn      {@code UC_<ARCH>_INS_<INSN>} constant, e.g.
     *                  {@code UC_X86_INS_IN} or {@code UC_ARM64_INS_MRS}
     * @param user_data User data to be passed to the callback function each
     *                  time the event is triggered
     * @return A value that can be passed to {@link #hook_del} to unregister
     *         this hook
     */
    public long hook_add(InstructionHook callback, int insn, Object user_data)
            throws UnicornException {
        return hook_add(callback, insn, 1, 0, user_data);
    }

    /**
     * Register a hook for the X86 IN instruction.
     * The registered callback will be called whenever an IN instruction
     * is executed.
     * 
     * @param callback  Object implementing the {@link InHook} interface
     * @param user_data User data to be passed to the callback function each
     *                  time the event is triggered
     * @return A value that can be passed to {@link #hook_del} to unregister
     *         this hook
     */
    public long hook_add(InHook callback, Object user_data)
            throws UnicornException {
        return hook_add(callback, UC_X86_INS_IN, user_data);
    }

    /**
     * Register a hook for the X86 OUT instruction.
     * The registered callback will be called whenever an OUT instruction
     * is executed.
     * 
     * @param callback  Object implementing the {@link InHook} interface
     * @param user_data User data to be passed to the callback function each
     *                  time the event is triggered
     * @return A value that can be passed to {@link #hook_del} to unregister
     *         this hook
     */
    public long hook_add(OutHook callback, Object user_data)
            throws UnicornException {
        return hook_add(callback, UC_X86_INS_OUT, user_data);
    }

    /** @deprecated Use {@code hook_add(callback, UC_X86_INS_SYSCALL, begin,
     *              end, user_data)} or {@code hook_add(callback,
     *              UC_X86_INS_SYSENTER, begin, end, user_data)} instead.
     */
    @Deprecated
    public long hook_add(SyscallHook callback, Object user_data)
            throws UnicornException {
        // Old implementation only registered SYSCALL, not SYSENTER.
        // Since this is deprecated anyway, we retain the old behaviour.
        return hook_add(callback, UC_X86_INS_SYSCALL, user_data);
    }

    /**
     * Register a {@code UC_HOOK_CODE} hook. The hook function will be
     * invoked when an instruction is executed from the address range
     * begin <= PC <= end. For the special case in which begin > end, the
     * callback will be invoked for ALL instructions.
     *
     * @param callback  Implementation of a {@link CodeHook} interface
     * @param begin     Start address of hooking range
     * @param end       End address of hooking range
     * @param user_data User data to be passed to the callback function each
     *                  time the event is triggered
     * @return A value that can be passed to {@link #hook_del} to unregister
     *         this hook
     */
    public long hook_add(CodeHook callback, long begin, long end,
            Object user_data)
            throws UnicornException {
        return registerHook(callback, _hook_add(nativePtr, UC_HOOK_CODE,
            callback, user_data, begin, end));
    }

    /**
     * Register a {@code UC_HOOK_BLOCK} hook. The hook function will be
     * invoked when a basic block is entered and the address of the basic
     * block (BB) falls in the range begin <= BB <= end. For the special case
     * in which begin > end, the callback will be invoked whenver any basic
     * block is entered.
     *
     * @param callback  Implementation of a {@link BlockHook} interface
     * @param begin     Start address of hooking range
     * @param end       End address of hooking range
     * @param user_data User data to be passed to the callback function each
     *                  time the event is triggered
     * @return A value that can be passed to {@link #hook_del} to unregister
     *         this hook
     */
    public long hook_add(BlockHook callback, long begin, long end,
            Object user_data)
            throws UnicornException {
        return registerHook(callback, _hook_add(nativePtr, UC_HOOK_BLOCK,
            callback, user_data, begin, end));
    }

    /**
     * Register a {@code UC_HOOK_MEM_VALID} hook
     * ({@code UC_HOOK_MEM_[READ,WRITE,FETCH]} and/or
     * {@code UC_HOOK_MEM_READ_AFTER}. The registered callback function will
     * be invoked whenever a corresponding memory operation is performed
     * within the address range begin <= addr <= end. For the special case in
     * which begin > end, the callback will be invoked for ALL memory
     * operations.
     *
     * @param callback  Implementation of a {@link MemHook} interface
     * @param type      Bitwise OR of {@code UC_HOOK_MEM_*} constants for
     *                  valid memory events
     * @param begin     Start address of memory range
     * @param end       End address of memory range
     * @param user_data User data to be passed to the callback function each
     *                  time the event is triggered
     * @return A value that can be passed to {@link #hook_del} to unregister
     *         this hook
     */
    public long hook_add(MemHook callback, int type, long begin, long end,
            Object user_data)
            throws UnicornException {
        return registerHook(callback,
            _hook_add(nativePtr, type, callback, user_data, begin, end));
    }

    /**
     * Register a {@code UC_HOOK_MEM_*_UNMAPPED} and/or
     * {@code UC_HOOK_MEM_*_PROT} hook.
     * The hook function will be invoked whenever a memory operation is
     * attempted from an invalid or protected memory address within the address
     * range begin <= addr <= end. For the special case in which begin > end,
     * the callback will be invoked for ALL invalid memory operations.
     *
     * @param callback  Implementation of a {@link EventMemHook} interface
     * @param type      Bitwise OR of {@code UC_HOOK_MEM_*} constants for
     *                  invalid memory events.
     * @param begin     Start address of memory range
     * @param end       End address of memory range
     * @param user_data User data to be passed to the callback function each
     *                  time the event is triggered
     * @return A value that can be passed to {@link #hook_del} to unregister
     *         this hook
     */
    public long hook_add(EventMemHook callback, int type, long begin, long end,
            Object user_data)
            throws UnicornException {
        return registerHook(callback,
            _hook_add(nativePtr, type, callback, user_data, begin, end));
    }

    /**
     * Register a {@code UC_HOOK_MEM_*_UNMAPPED} and/or
     * {@code UC_HOOK_MEM_*_PROT} hook for all memory addresses.
     * 
     * @param callback  Implementation of a {@link EventMemHook} interface
     * @param type      Bitwise OR of {@code UC_HOOK_MEM_*} constants for
     *                  invalid memory events.
     * @param user_data User data to be passed to the callback function each
     *                  time the event is triggered
     * @return A value that can be passed to {@link #hook_del} to unregister
     *         this hook
     */
    public long hook_add(EventMemHook callback, int type, Object user_data)
            throws UnicornException {
        return registerHook(callback,
            _hook_add(nativePtr, type, callback, user_data, 1, 0));
    }

    /**
     * Register a {@code UC_HOOK_INSN_INVALID} hook. The hook function will be
     * invoked whenever an invalid instruction is encountered.
     *
     * @param callback  Implementation of a {@link InvalidInstructionHook}
     *                  interface
     * @param user_data User data to be passed to the callback function each
     *                  time the event is triggered
     * @return A value that can be passed to {@link #hook_del} to unregister
     *         this hook
     */
    public long hook_add(InvalidInstructionHook callback,
            Object user_data) {
        return registerHook(callback, _hook_add(nativePtr, UC_HOOK_INSN_INVALID,
            callback, user_data, 1, 0));
    }

    /**
     * Register a {@code UC_HOOK_EDGE_GENERATED} hook. The hook function will
     * be invoked whenever a jump is made to a new (untranslated) basic block
     * with a start address in the range of begin <= pc <= end. For the
     * special case in which begin > end, the callback will be invoked for ALL
     * new edges.
     *
     * @param callback  Implementation of a {@link EdgeGeneratedHook} interface
     * @param begin     Start address
     * @param end       End address
     * @param user_data User data to be passed to the callback function each
     *                  time the event is triggered
     * @return A value that can be passed to {@link #hook_del} to unregister
     *         this hook
     */
    public long hook_add(EdgeGeneratedHook callback, long begin, long end,
            Object user_data)
            throws UnicornException {
        return registerHook(callback, _hook_add(nativePtr,
            UC_HOOK_EDGE_GENERATED, callback, user_data, begin, end));
    }

    /**
     * Register a {@code UC_HOOK_TCG_OPCODE} hook. The hook function will be
     * invoked whenever a matching instruction is executed within the
     * registered range.
     *
     * @param callback  Implementation of a {@link TcgOpcodeHook} interface
     * @param begin     Start address
     * @param end       End address
     * @param opcode    Opcode to hook. One of the {@code UC_TCG_OP_*}
     *                  constants.
     * @param flags     Flags to filter opcode matches. A bitwise-OR of
     *                  {@code UC_TCG_OP_FLAG_*} constants.
     * @param user_data User data to be passed to the callback function each
     *                  time the event is triggered
     * @return A value that can be passed to {@link #hook_del} to unregister
     *         this hook
     */
    public long hook_add(TcgOpcodeHook callback, long begin, long end,
            int opcode, int flags,
            Object user_data)
            throws UnicornException {
        return registerHook(callback, _hook_add(nativePtr, UC_HOOK_TCG_OPCODE,
            callback, user_data, begin, end, opcode, flags));
    }

    /**
     * Register a {@code UC_HOOK_TLB_FILL} hook. The hook function will be
     * invoked to map a virtual address within the registered range to a
     * physical address. These hooks will only be called if the TLB mode (set
     * via {@link #ctl_tlb_mode}) is set to {@code UC_TLB_VIRTUAL}.
     *
     * @param callback  Implementation of a {@link TlbFillHook} interface
     * @param begin     Start address
     * @param end       End address
     * @param user_data User data to be passed to the callback function each
     *                  time the event is triggered
     * @return A value that can be passed to {@link #hook_del} to unregister
     *         this hook
     */
    public long hook_add(TlbFillHook callback, long begin, long end,
            Object user_data) throws UnicornException {
        return registerHook(callback, _hook_add(nativePtr, UC_HOOK_TLB_FILL,
            callback, user_data, begin, end));
    }

    /** Remove a hook that was previously registered.
     * 
     * @param hook The return value from any {@code hook_add} function.
     */
    public void hook_del(long hook) throws UnicornException {
        if (hooks.containsKey(hook)) {
            HookWrapper wrapper = hooks.remove(hook);
            _hook_del(nativePtr, wrapper.nativePtr);
        } else {
            throw new UnicornException("Hook is not registered!");
        }
    }

    /** Remove all registrations for a given {@link Hook} object.
     * 
     * @param hook A {@link Hook} object to unregister.
     */
    public void hook_del(Hook hook) throws UnicornException {
        if (hook == null) {
            // we use null for "special" hooks that can't be _hook_del'd
            throw new NullPointerException("hook must not be null");
        }
        Iterator<Map.Entry<Long, HookWrapper>> it = hooks.entrySet().iterator();
        while (it.hasNext()) {
            HookWrapper wrapper = it.next().getValue();
            if (wrapper.hook == hook) {
                it.remove();
                _hook_del(nativePtr, wrapper.nativePtr);
            }
        }
    }

    /**
     * Create a memory-mapped I/O range.
     *
     * @param address  Starting memory address of the MMIO area
     * @param size     Size of the MMIO area
     * @param read_cb  Implementation of {@link MmioReadHandler} to handle
     *                 read operations, or {@code null} for non-readable
     *                 memory
     * @param user_data_read User data to be passed to the read callback
     * @param write_cb Implementation of {@link MmioWriteHandler} to handle
     *                 write operations, or {@code null} for non-writable
     *                 memory
     * @param user_data_write User data to be passed to the write callback
     * @throws UnicornException
     */
    public void mmio_map(long address, long size, MmioReadHandler read_cb,
            Object user_data_read, MmioWriteHandler write_cb,
            Object user_data_write)
            throws UnicornException {
        /* TODO: Watch mem_unmap to know when it's safe to release the hook. */
        long[] hooks = _mmio_map(nativePtr, address, size, read_cb,
            user_data_read, write_cb, user_data_write);
        for (long hook : hooks) {
            registerHook(null, hook);
        }
    }

    /**
     * Map a range of memory, automatically allocating backing host memory.
     *
     * @param address Base address of the memory range
     * @param size    Size of the memory block
     * @param perms   Permissions on the memory block. A bitwise combination
     *                of {@code UC_PROT_*} constants.
     */
    public void mem_map(long address, long size, int perms)
            throws UnicornException {
        _mem_map(nativePtr, address, size, perms);
    }

    /**
     * Map a range of memory, backed by an existing region of host memory.
     * This API enables direct access to emulator memory without going through
     * {@link #mem_read} and {@link #mem_write}.
     * <p>
     * Usage note: The mapped memory region will correspond to the entire
     * passed-in Buffer from position 0 (the origin) up to its capacity. The
     * capacity MUST be a multiple of the page size. The current position and
     * limit will be ignored.
     * You can use {@link Buffer#slice()} to get a new Buffer sharing the same
     * memory region, with the origin set to the current {@code position} and
     * the capacity set to {@code limit - position}.
     *
     * @param address Base address of the memory range
     * @param buf     Direct Buffer referencing the memory to map into the
     *                emulator. IMPORTANT: You are responsible for ensuring
     *                that this Buffer remains alive as long as the memory
     *                remains mapped!
     * @param perms   Permissions on the memory block. A bitwise combination
     *                of {@code UC_PROT_*} constants.
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
     * @param perms   Permissions on the memory block. A bitwise combination
     *                of {@code UC_PROT_*} constants.
     */
    public void mem_protect(long address, long size, int perms)
            throws UnicornException {
        _mem_protect(nativePtr, address, size, perms);
    }

    /**
     * Retrieve all memory regions mapped by {@link #mem_map},
     * {@link #mmio_map} and {@link #mem_map_ptr}.
     * NOTE: memory regions may be split by {@link #mem_unmap}.
     *
     * @return array of mapped regions.
     */
    public MemRegion[] mem_regions() throws UnicornException {
        return _mem_regions(nativePtr);
    }

    /**
     * Save the current CPU state of the emulator. The resulting context can be
     * restored on any emulator with the same {@code arch} and {@code mode}.
     */
    public Context context_save() throws UnicornException {
        long ptr = _context_alloc(nativePtr);
        Context context = new Context();
        context.nativePtr = ptr;
        context.arch = arch;
        context.mode = mode;
        _context_save(nativePtr, ptr);
        return context;
    }

    /**
     * Update a {@link Context} object with the current CPU state of the
     * emulator.
     */
    public void context_update(Context context) throws UnicornException {
        if (context.arch != arch || context.mode != mode) {
            throw new UnicornException(
                "Context is not compatible with this Unicorn");
        }
        _context_save(nativePtr, context.nativePtr);
    }

    /**
     * Restore the current CPU context from a saved copy.
     */
    public void context_restore(Context context) throws UnicornException {
        if (context.arch != arch || context.mode != mode) {
            throw new UnicornException(
                "Context is not compatible with this Unicorn");
        }
        _context_restore(nativePtr, context.nativePtr);
    }

    /* Obsolete context implementation, for backwards compatibility only */
    /** Structure to track contexts allocated using context_alloc, for
     * memory safety. Not used for contexts created using
     * {@link #context_save()}.
     */
    private static Hashtable<Long, Context> allocedContexts = new Hashtable<>();

    /** @deprecated Use {@link #context_save()} instead. */
    @Deprecated
    public long context_alloc() {
        long ptr = _context_alloc(nativePtr);
        Context context = new Context();
        context.nativePtr = ptr;
        context.arch = arch;
        context.mode = mode;
        long index = nextAllocCounter();
        allocedContexts.put(index, context);
        return index;
    }

    /** @deprecated Do not use this method.
     * 
     * @param handle Value previously returned by {@link #context_alloc}
     */
    @Deprecated
    public void free(long handle) {
        allocedContexts.remove(handle);
    }

    /** @deprecated Use {@link #context_save()} or {@link #context_update}
     * instead */
    @Deprecated
    public void context_save(long context) {
        context_update(allocedContexts.get(context));
    }

    /** @deprecated Use {@link #context_restore(Context)} instead */
    @Deprecated
    public void context_restore(long context) {
        context_restore(allocedContexts.get(context));
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
