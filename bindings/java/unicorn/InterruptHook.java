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

/** Callback for {@code UC_HOOK_INTR} */
public interface InterruptHook extends Hook {
    /** Called when a CPU interrupt occurs.
     * 
     * @param u       {@link Unicorn} instance firing this hook
     * @param intno   CPU-specific interrupt number
     * @param user    user data provided when registering this hook
     */
    public void hook(Unicorn u, int intno, Object user);
}
