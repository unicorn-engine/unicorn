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

/** Callback for {@code UC_HOOK_EDGE_GENERATED} */
public interface EdgeGeneratedHook extends Hook {
    /** Called whenever a jump is made to a new (untranslated) basic block.
     * 
     * @param u       {@link Unicorn} instance firing this hook
     * @param cur_tb  newly translated block being entered
     * @param prev_tb previous block being exited
     * @param user    user data provided when registering this hook
     */
    public void hook(Unicorn u, TranslationBlock cur_tb,
            TranslationBlock prev_tb, Object user);
}
