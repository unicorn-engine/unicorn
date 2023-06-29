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

/** Callback for {@code UC_HOOK_INSN_INVALID} */
public interface InvalidInstructionHook extends Hook {
    /** Called when an invalid instruction is encountered.
     * 
     * @param u    {@link Unicorn} instance firing this hook
     * @param user user data provided when registering this hook
     * @return     {@code true} to mark the exception as handled. Emulation
     *             will stop without raising an invalid instruction exception.
     *             If no hooks return {@code true}, emulation  will stop with
     *             an invalid instruction exception.
     */
    public boolean hook(Unicorn u, Object user);
}
