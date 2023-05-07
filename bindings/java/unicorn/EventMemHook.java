/*

Java bindings for the Unicorn Emulator Engine

Copyright(c) 2015 Chris Eagle

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

/** Callback for {@code UC_HOOK_MEM_INVALID}
 * (<code>UC_HOOK_MEM_{READ,WRITE,FETCH}_{UNMAPPED,PROT}</code>) */
public interface EventMemHook extends Hook {
    /** Called when an invalid memory access occurs within the registered
     * range.
     * 
     * @param u       {@link Unicorn} instance firing this hook
     * @param type    type of the memory access and violation: one of
     *                <code>UC_MEM_{READ,WRITE,FETCH}_{UNMAPPED,PROT}</code>
     * @param address address of the memory access
     * @param size    size of the memory access
     * @param value   value written ({@code UC_MEM_WRITE_*} only)
     * @param user    user data provided when registering this hook
     * @return        {@code true} to mark the exception as handled, which
     *                will retry the memory access. If no hooks return
     *                {@code true}, the memory access will fail and a CPU
     *                exception will be raised.
     */
    public boolean hook(Unicorn u, int type, long address, int size, long value,
            Object user);
}
