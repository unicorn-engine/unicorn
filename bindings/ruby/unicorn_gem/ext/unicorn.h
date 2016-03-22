/*

Ruby bindings for the Unicorn Emulator Engine

Copyright(c) 2016 Sascha Schirra

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
VALUE m_uc_initialize(VALUE self, VALUE arch, VALUE mode);
VALUE m_uc_emu_start(int argc, VALUE* argv, VALUE self);
VALUE m_uc_emu_stop(VALUE self);
VALUE m_uc_reg_read(VALUE self, VALUE reg_id);
VALUE m_uc_reg_write(VALUE self, VALUE reg_id, VALUE reg_value);
VALUE m_uc_mem_read(VALUE self, VALUE address, VALUE size);
VALUE m_uc_mem_write(VALUE self, VALUE address, VALUE bytes);
VALUE m_uc_mem_map(int argc, VALUE* argv, VALUE self);
VALUE m_uc_mem_unmap(VALUE self, VALUE address, VALUE size);
VALUE m_uc_mem_protect(VALUE self, VALUE address, VALUE size, VALUE perms);
VALUE m_uc_hook_add(int argc, VALUE* argv, VALUE self);
VALUE m_uc_hook_del(VALUE self, VALUE hook);
VALUE m_uc_query(VALUE self, VALUE query_mode);