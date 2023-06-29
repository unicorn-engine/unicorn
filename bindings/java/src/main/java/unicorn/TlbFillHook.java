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

/** Callback for {@code UC_HOOK_TLB_FILL} */
public interface TlbFillHook extends Hook {
    /** Called to map a virtual address within the registered range to a
     * physical address. The resulting mapping is cached in the QEMU TLB.
     * These hooks are only called if the TLB mode (set via
     * {@link Unicorn#ctl_tlb_mode}) is set to {@code UC_TLB_VIRTUAL}.
     * 
     * @param u       {@link Unicorn} instance firing this hook
     * @param vaddr   virtual address being mapped
     * @param type    type of memory access ({@code UC_MEM_READ},
     *                {@code UC_MEM_WRITE} or {@code UC_MEM_FETCH}).
     * @param user    user data provided when registering this hook
     * @return        the page-aligned physical address ORed with the page
     *                protection bits ({@code UC_PROT_*}). Return -1L to
     *                indicate an unmapped address; if all hooks return -1L,
     *                the memory access will fail and raise a CPU exception.
     */
    public long hook(Unicorn u, long vaddr, int type, Object user);
}
