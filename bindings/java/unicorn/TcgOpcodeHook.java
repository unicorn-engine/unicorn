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

/** Callback for {@code UC_HOOK_TCG_OPCODE} */
public interface TcgOpcodeHook extends Hook {
    /** Called on every instruction of the registered type(s) within the
     * registered range. For example, a {@code UC_TCG_OP_SUB} hook fires on
     * every instruction that contains a subtraction operation, unless
     * otherwise filtered.
     * 
     * @param u       {@link Unicorn} instance firing this hook
     * @param address address of the instruction
     * @param arg1    first argument to the instruction
     * @param arg2    second argument to the instruction
     * @param size    size of the operands (currently, 32 or 64)
     * @param user    user data provided when registering this hook
     */
    public void hook(Unicorn u, long address, long arg1, long arg2, int size,
            Object user);
}
