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

module UcError =

    let toErrorDesc(err: Int32) =
        match err with
        | 0 -> "UC_ERR_OK"
        | 1 -> "UC_ERR_NOMEM"
        | 2 -> "UC_ERR_ARCH"
        | 3 -> "UC_ERR_HANDLE"
        | 4 -> "UC_ERR_MODE"
        | 5 -> "UC_ERR_VERSION"
        | 6 -> "UC_ERR_READ_INVALID"
        | 7 -> "UC_ERR_WRITE_INVALID"
        | 8 -> "UC_ERR_FETCH_INVALID"
        | 9 -> "UC_ERR_CODE_INVALID"
        | 10 -> "UC_ERR_HOOK"
        | 11 -> "UC_ERR_INSN_INVALID"
        | 12 -> "UC_ERR_MAP"
        | 13 -> "UC_ERR_WRITE_PROT"
        | 14 -> "UC_ERR_READ_PROT"
        | 15 -> "UC_ERR_FETCH_PROT"
        | 16 -> "UC_ERR_ARG"
        | 17 -> "UC_ERR_READ_UNALIGNED"
        | 18 -> "UC_ERR_WRITE_UNALIGNED"
        | 19 -> "UC_ERR_FETCH_UNALIGNED"
        | _ -> String.Empty

