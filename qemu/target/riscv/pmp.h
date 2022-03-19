/*
 * QEMU RISC-V PMP (Physical Memory Protection)
 *
 * Author: Daire McNamara, daire.mcnamara@emdalo.com
 *         Ivan Griffin, ivan.griffin@emdalo.com
 *
 * This provides a RISC-V Physical Memory Protection interface
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef RISCV_PMP_H
#define RISCV_PMP_H

typedef enum {
    PMP_READ  = 1 << 0,
    PMP_WRITE = 1 << 1,
    PMP_EXEC  = 1 << 2,
    PMP_LOCK  = 1 << 7
} pmp_priv_t;

typedef enum {
    PMP_AMATCH_OFF,  /* Null (off)                            */
    PMP_AMATCH_TOR,  /* Top of Range                          */
    PMP_AMATCH_NA4,  /* Naturally aligned four-byte region    */
    PMP_AMATCH_NAPOT /* Naturally aligned power-of-two region */
} pmp_am_t;

typedef struct {
    target_ulong addr_reg;
    uint8_t  cfg_reg;
} pmp_entry_t;

typedef struct {
    target_ulong sa;
    target_ulong ea;
} pmp_addr_t;

typedef struct {
    pmp_entry_t pmp[MAX_RISCV_PMPS];
    pmp_addr_t  addr[MAX_RISCV_PMPS];
    uint32_t num_rules;
} pmp_table_t;

void pmpcfg_csr_write(CPURISCVState *env, uint32_t reg_index,
    target_ulong val);
target_ulong pmpcfg_csr_read(CPURISCVState *env, uint32_t reg_index);
void pmpaddr_csr_write(CPURISCVState *env, uint32_t addr_index,
    target_ulong val);
target_ulong pmpaddr_csr_read(CPURISCVState *env, uint32_t addr_index);
bool pmp_hart_has_privs(CPURISCVState *env, target_ulong addr,
    target_ulong size, pmp_priv_t priv, target_ulong mode);

#endif
