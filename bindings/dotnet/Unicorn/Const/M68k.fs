(*

.NET bindings for the UnicornEngine Emulator Engine

Copyright(c) 2015 Antonio Parata

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

*)

namespace UnicornEngine.Const

open System

[<AutoOpen>]
module M68k =

    // M68K registers
    let UC_M68K_REG_INVALID = 0
    let UC_M68K_REG_A0 = 1
    let UC_M68K_REG_A1 = 2
    let UC_M68K_REG_A2 = 3
    let UC_M68K_REG_A3 = 4
    let UC_M68K_REG_A4 = 5
    let UC_M68K_REG_A5 = 6
    let UC_M68K_REG_A6 = 7
    let UC_M68K_REG_A7 = 8
    let UC_M68K_REG_D0 = 9
    let UC_M68K_REG_D1 = 10
    let UC_M68K_REG_D2 = 11
    let UC_M68K_REG_D3 = 12
    let UC_M68K_REG_D4 = 13
    let UC_M68K_REG_D5 = 14
    let UC_M68K_REG_D6 = 15
    let UC_M68K_REG_D7 = 16
    let UC_M68K_REG_SR = 17
    let UC_M68K_REG_PC = 18
    let UC_M68K_REG_ENDING = 19 
