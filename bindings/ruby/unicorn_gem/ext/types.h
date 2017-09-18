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

typedef struct uc_x86_float80 {
    uint64_t mantissa;
    uint16_t exponent;
} uc_x86_float80;


struct hook {
  uc_hook trace;
  VALUE cb;
  VALUE ud;
  VALUE rUc;
};
