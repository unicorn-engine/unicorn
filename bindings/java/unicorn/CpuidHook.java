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

/** Callback for {@code UC_HOOK_INSN} with {@code UC_X86_INS_CPUID} */
public interface CpuidHook extends InstructionHook {
    /** Called to handle an x86 CPUID instruction.
     * 
     * @param u       {@link Unicorn} instance firing this hook
     * @param user    user data provided when registering this hook
     * @return        1 to skip the instruction (marking it as handled),
     *                0 to let QEMU handle it
     */
    public int hook(Unicorn u, Object user);
}
