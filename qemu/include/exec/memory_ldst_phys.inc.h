/*
 *  Physical memory access templates
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *  Copyright (c) 2015 Linaro, Inc.
 *  Copyright (c) 2016 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#ifdef TARGET_ENDIANNESS
static inline uint32_t glue(ldl_phys, SUFFIX)(struct uc_struct *uc, ARG1_DECL, hwaddr addr)
{
    return glue(address_space_ldl, SUFFIX)(uc, ARG1, addr,
                                           MEMTXATTRS_UNSPECIFIED, NULL);
}

static inline uint64_t glue(ldq_phys, SUFFIX)(struct uc_struct *uc, ARG1_DECL, hwaddr addr)
{
    return glue(address_space_ldq, SUFFIX)(uc, ARG1, addr,
                                           MEMTXATTRS_UNSPECIFIED, NULL);
}

static inline uint32_t glue(lduw_phys, SUFFIX)(struct uc_struct *uc, ARG1_DECL, hwaddr addr)
{
    return glue(address_space_lduw, SUFFIX)(uc, ARG1, addr,
                                            MEMTXATTRS_UNSPECIFIED, NULL);
}

static inline void glue(stl_phys, SUFFIX)(struct uc_struct *uc, ARG1_DECL, hwaddr addr, uint32_t val)
{
    glue(address_space_stl, SUFFIX)(uc, ARG1, addr, val,
                                    MEMTXATTRS_UNSPECIFIED, NULL);
}

static inline void glue(stw_phys, SUFFIX)(struct uc_struct *uc, ARG1_DECL, hwaddr addr, uint32_t val)
{
    glue(address_space_stw, SUFFIX)(uc, ARG1, addr, val,
                                    MEMTXATTRS_UNSPECIFIED, NULL);
}

static inline void glue(stq_phys, SUFFIX)(struct uc_struct *uc, ARG1_DECL, hwaddr addr, uint64_t val)
{
    glue(address_space_stq, SUFFIX)(uc, ARG1, addr, val,
                                    MEMTXATTRS_UNSPECIFIED, NULL);
}
#else
static inline uint32_t glue(ldl_le_phys, SUFFIX)(struct uc_struct *uc, ARG1_DECL, hwaddr addr)
{
    return glue(address_space_ldl_le, SUFFIX)(uc, ARG1, addr,
                                              MEMTXATTRS_UNSPECIFIED, NULL);
}

static inline uint32_t glue(ldl_be_phys, SUFFIX)(struct uc_struct *uc, ARG1_DECL, hwaddr addr)
{
    return glue(address_space_ldl_be, SUFFIX)(uc, ARG1, addr,
                                              MEMTXATTRS_UNSPECIFIED, NULL);
}

static inline uint64_t glue(ldq_le_phys, SUFFIX)(struct uc_struct *uc, ARG1_DECL, hwaddr addr)
{
    return glue(address_space_ldq_le, SUFFIX)(uc, ARG1, addr,
                                              MEMTXATTRS_UNSPECIFIED, NULL);
}

static inline uint64_t glue(ldq_be_phys, SUFFIX)(struct uc_struct *uc, ARG1_DECL, hwaddr addr)
{
    return glue(address_space_ldq_be, SUFFIX)(uc, ARG1, addr,
                                              MEMTXATTRS_UNSPECIFIED, NULL);
}

static inline uint32_t glue(ldub_phys, SUFFIX)(struct uc_struct *uc, ARG1_DECL, hwaddr addr)
{
    return glue(address_space_ldub, SUFFIX)(uc, ARG1, addr,
                                            MEMTXATTRS_UNSPECIFIED, NULL);
}

static inline uint32_t glue(lduw_le_phys, SUFFIX)(struct uc_struct *uc, ARG1_DECL, hwaddr addr)
{
    return glue(address_space_lduw_le, SUFFIX)(uc, ARG1, addr,
                                               MEMTXATTRS_UNSPECIFIED, NULL);
}

static inline uint32_t glue(lduw_be_phys, SUFFIX)(struct uc_struct *uc, ARG1_DECL, hwaddr addr)
{
    return glue(address_space_lduw_be, SUFFIX)(uc, ARG1, addr,
                                               MEMTXATTRS_UNSPECIFIED, NULL);
}

static inline void glue(stl_le_phys, SUFFIX)(struct uc_struct *uc, ARG1_DECL, hwaddr addr, uint32_t val)
{
    glue(address_space_stl_le, SUFFIX)(uc, ARG1, addr, val,
                                       MEMTXATTRS_UNSPECIFIED, NULL);
}

static inline void glue(stl_be_phys, SUFFIX)(struct uc_struct *uc, ARG1_DECL, hwaddr addr, uint32_t val)
{
    glue(address_space_stl_be, SUFFIX)(uc, ARG1, addr, val,
                                       MEMTXATTRS_UNSPECIFIED, NULL);
}

static inline void glue(stb_phys, SUFFIX)(struct uc_struct *uc, ARG1_DECL, hwaddr addr, uint32_t val)
{
    glue(address_space_stb, SUFFIX)(uc, ARG1, addr, val,
                                    MEMTXATTRS_UNSPECIFIED, NULL);
}

static inline void glue(stw_le_phys, SUFFIX)(struct uc_struct *uc, ARG1_DECL, hwaddr addr, uint32_t val)
{
    glue(address_space_stw_le, SUFFIX)(uc, ARG1, addr, val,
                                       MEMTXATTRS_UNSPECIFIED, NULL);
}

static inline void glue(stw_be_phys, SUFFIX)(struct uc_struct *uc, ARG1_DECL, hwaddr addr, uint32_t val)
{
    glue(address_space_stw_be, SUFFIX)(uc, ARG1, addr, val,
                                       MEMTXATTRS_UNSPECIFIED, NULL);
}

static inline void glue(stq_le_phys, SUFFIX)(struct uc_struct *uc, ARG1_DECL, hwaddr addr, uint64_t val)
{
    glue(address_space_stq_le, SUFFIX)(uc, ARG1, addr, val,
                                       MEMTXATTRS_UNSPECIFIED, NULL);
}

static inline void glue(stq_be_phys, SUFFIX)(struct uc_struct *uc, ARG1_DECL, hwaddr addr, uint64_t val)
{
    glue(address_space_stq_be, SUFFIX)(uc, ARG1, addr, val,
                                       MEMTXATTRS_UNSPECIFIED, NULL);
}
#endif

#undef ARG1_DECL
#undef ARG1
#undef SUFFIX
#undef TARGET_ENDIANNESS
