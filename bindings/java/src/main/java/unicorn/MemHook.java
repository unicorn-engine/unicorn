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

/** Callback for {@code UC_HOOK_MEM_VALID}
 * (<code>UC_HOOK_MEM_{READ,WRITE,FETCH}</code> and/or
 * {@code UC_HOOK_MEM_READ_AFTER}) */
public interface MemHook extends Hook {
    /** Called when a valid memory access occurs within the registered range.
     * 
     * @param u       {@link Unicorn} instance firing this hook
     * @param type    type of the memory access: one of {@code UC_MEM_READ},
     *                {@code UC_MEM_WRITE} or {@code UC_MEM_READ_AFTER}.
     * @param address address of the memory access
     * @param size    size of the memory access
     * @param value   value read ({@code UC_MEM_READ_AFTER} only) or written
     *                ({@code UC_MEM_WRITE} only). Not meaningful for
     *                {@code UC_MEM_READ} events.
     * @param user    user data provided when registering this hook
     */
    public void hook(Unicorn u, int type, long address, int size, long value,
            Object user);
}
