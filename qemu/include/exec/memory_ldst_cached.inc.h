/*
 *  Memory access templates for MemoryRegionCache
 *
 *  Copyright (c) 2018 Red Hat, Inc.
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

#ifdef UNICORN_ARCH_POSTFIX
#define ADDRESS_SPACE_LD_CACHED(size) \
    glue(glue(glue(address_space_ld, size), glue(ENDIANNESS, _cached)), UNICORN_ARCH_POSTFIX)
#define ADDRESS_SPACE_LD_CACHED_SLOW(size) \
    glue(glue(glue(address_space_ld, size), glue(ENDIANNESS, _cached_slow)), UNICORN_ARCH_POSTFIX)
#define LD_P(size) \
    glue(glue(ld, size), glue(ENDIANNESS, _p))
#else
#define ADDRESS_SPACE_LD_CACHED(size) \
    glue(glue(address_space_ld, size), glue(ENDIANNESS, _cached))
#define ADDRESS_SPACE_LD_CACHED_SLOW(size) \
    glue(glue(address_space_ld, size), glue(ENDIANNESS, _cached_slow))
#define LD_P(size) \
    glue(glue(ld, size), glue(ENDIANNESS, _p))
#endif

static inline uint32_t ADDRESS_SPACE_LD_CACHED(l)(struct uc_struct *uc, MemoryRegionCache *cache,
    hwaddr addr, MemTxAttrs attrs, MemTxResult *result)
{
    assert(addr < cache->len && 4 <= cache->len - addr);
    if (likely(cache->ptr)) {
        return LD_P(l)((char *)cache->ptr + addr);
    } else {
        return ADDRESS_SPACE_LD_CACHED_SLOW(l)(uc, cache, addr, attrs, result);
    }
}

static inline uint64_t ADDRESS_SPACE_LD_CACHED(q)(struct uc_struct *uc, MemoryRegionCache *cache,
    hwaddr addr, MemTxAttrs attrs, MemTxResult *result)
{
    assert(addr < cache->len && 8 <= cache->len - addr);
    if (likely(cache->ptr)) {
        return LD_P(q)((char *)cache->ptr + addr);
    } else {
        return ADDRESS_SPACE_LD_CACHED_SLOW(q)(uc, cache, addr, attrs, result);
    }
}

static inline uint32_t ADDRESS_SPACE_LD_CACHED(uw)(struct uc_struct *uc, MemoryRegionCache *cache,
    hwaddr addr, MemTxAttrs attrs, MemTxResult *result)
{
    assert(addr < cache->len && 2 <= cache->len - addr);
    if (likely(cache->ptr)) {
        return LD_P(uw)((char *)cache->ptr + addr);
    } else {
        return ADDRESS_SPACE_LD_CACHED_SLOW(uw)(uc, cache, addr, attrs, result);
    }
}

#undef ADDRESS_SPACE_LD_CACHED
#undef ADDRESS_SPACE_LD_CACHED_SLOW
#undef LD_P

#ifdef UNICORN_ARCH_POSTFIX
#define ADDRESS_SPACE_ST_CACHED(size) \
    glue(glue(glue(address_space_st, size), glue(ENDIANNESS, _cached)), UNICORN_ARCH_POSTFIX)
#define ADDRESS_SPACE_ST_CACHED_SLOW(size) \
    glue(glue(glue(address_space_st, size), glue(ENDIANNESS, _cached_slow)), UNICORN_ARCH_POSTFIX)
#define ST_P(size) \
    glue(glue(st, size), glue(ENDIANNESS, _p))
#else
#define ADDRESS_SPACE_ST_CACHED(size) \
    glue(glue(address_space_st, size), glue(ENDIANNESS, _cached))
#define ADDRESS_SPACE_ST_CACHED_SLOW(size) \
    glue(glue(address_space_st, size), glue(ENDIANNESS, _cached_slow))
#define ST_P(size) \
    glue(glue(st, size), glue(ENDIANNESS, _p))
#endif

static inline void ADDRESS_SPACE_ST_CACHED(l)(struct uc_struct *uc, MemoryRegionCache *cache,
    hwaddr addr, uint32_t val, MemTxAttrs attrs, MemTxResult *result)
{
    assert(addr < cache->len && 4 <= cache->len - addr);
    if (likely(cache->ptr)) {
        ST_P(l)((char *)cache->ptr + addr, val);
    } else {
        ADDRESS_SPACE_ST_CACHED_SLOW(l)(uc, cache, addr, val, attrs, result);
    }
}

static inline void ADDRESS_SPACE_ST_CACHED(w)(struct uc_struct *uc, MemoryRegionCache *cache,
    hwaddr addr, uint32_t val, MemTxAttrs attrs, MemTxResult *result)
{
    assert(addr < cache->len && 2 <= cache->len - addr);
    if (likely(cache->ptr)) {
        ST_P(w)((char *)cache->ptr + addr, val);
    } else {
        ADDRESS_SPACE_ST_CACHED_SLOW(w)(uc, cache, addr, val, attrs, result);
    }
}

static inline void ADDRESS_SPACE_ST_CACHED(q)(struct uc_struct *uc, MemoryRegionCache *cache,
    hwaddr addr, uint64_t val, MemTxAttrs attrs, MemTxResult *result)
{
    assert(addr < cache->len && 8 <= cache->len - addr);
    if (likely(cache->ptr)) {
        ST_P(q)((char *)cache->ptr + addr, val);
    } else {
        ADDRESS_SPACE_ST_CACHED_SLOW(q)(uc, cache, addr, val, attrs, result);
    }
}

#undef ADDRESS_SPACE_ST_CACHED
#undef ADDRESS_SPACE_ST_CACHED_SLOW
#undef ST_P

#undef ENDIANNESS
