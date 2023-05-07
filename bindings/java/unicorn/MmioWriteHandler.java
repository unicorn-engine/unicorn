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

/** Interface for handling writes to memory-mapped I/O, mapped via
 * {@link Unicorn#mmio_map} */
public interface MmioWriteHandler {
    /** Called when a memory write is made to an address in the mapped range.
     * 
     * @param u       {@link Unicorn} instance firing this hook
     * @param offset  offset of the request address from the start of the
     *                mapped range
     * @param size    size of the memory access, in bytes
     * @param value   value being written
     * @param user    user data provided when registering this hook
     */
    void write(Unicorn u, long offset, int size, long value, Object user_data);
}
