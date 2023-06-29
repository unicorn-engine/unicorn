/*

Java bindings for the Unicorn Emulator Engine

Copyright(c) 2023 Robert Xiao

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

/** Callback for {@code UC_HOOK_INSN} with {@code UC_ARM64_INS_MRS},
 * {@code UC_ARM64_INS_MSR}, {@code UC_ARM64_INS_SYS}
 * or {@code UC_ARM64_INS_SYSL} */
public interface Arm64SysHook extends InstructionHook {
    /** Called to handle an AArch64 MRS, MSR, SYS or SYSL instruction.
     * 
     * @param u       {@link Unicorn} instance firing this hook
     * @param reg     source or destination register
     *                ({@code UC_ARM64_REG_X*} constant)
     * @param cp_reg  coprocessor register specification
     *                ({@code .val} = current value of {@code reg})
     * @param user    user data provided when registering this hook
     * @return        1 to skip the instruction (marking it as handled),
     *                0 to let QEMU handle it
     */
    public int hook(Unicorn u, int reg, Arm64_CP cp_reg, Object user);
}
