/*
 * qht.c - QEMU Hash Table, designed to scale for read-mostly workloads.
 *
 * Copyright (C) 2016, Emilio G. Cota <cota@braap.org>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 *
 * Assumptions:
 * - NULL cannot be inserted/removed as a pointer value.
 * - Trying to insert an already-existing hash-pointer pair is OK. However,
 *   it is not OK to insert into the same hash table different hash-pointer
 *   pairs that have the same pointer value, but not the hashes.
 * - Lookups are performed under an RCU read-critical section; removals
 *   must wait for a grace period to elapse before freeing removed objects.
 *
 * Features:
 * - Reads (i.e. lookups and iterators) can be concurrent with other reads.
 *   Lookups that are concurrent with writes to the same bucket will retry
 *   via a seqlock; iterators acquire all bucket locks and therefore can be
 *   concurrent with lookups and are serialized wrt writers.
 * - Writes (i.e. insertions/removals) can be concurrent with writes to
 *   different buckets; writes to the same bucket are serialized through a lock.
 * - Optional auto-resizing: the hash table resizes up if the load surpasses
 *   a certain threshold. Resizing is done concurrently with readers; writes
 *   are serialized with the resize operation.
 *
 * The key structure is the bucket, which is cacheline-sized. Buckets
 * contain a few hash values and pointers; the u32 hash values are stored in
 * full so that resizing is fast. Having this structure instead of directly
 * chaining items has two advantages:
 * - Failed lookups fail fast, and touch a minimum number of cache lines.
 * - Resizing the hash table with concurrent lookups is easy.
 *
 * There are two types of buckets:
 * 1. "head" buckets are the ones allocated in the array of buckets in qht_map.
 * 2. all "non-head" buckets (i.e. all others) are members of a chain that
 *    starts from a head bucket.
 * Note that the seqlock and spinlock of a head bucket applies to all buckets
 * chained to it; these two fields are unused in non-head buckets.
 *
 * On removals, we move the last valid item in the chain to the position of the
 * just-removed entry. This makes lookups slightly faster, since the moment an
 * invalid entry is found, the (failed) lookup is over.
 *
 * Resizing is done by taking all bucket spinlocks (so that no other writers can
 * race with us) and then copying all entries into a new hash map. Then, the
 * ht->map pointer is set, and the old map is freed once no RCU readers can see
 * it anymore.
 *
 * Writers check for concurrent resizes by comparing ht->map before and after
 * acquiring their bucket lock. If they don't match, a resize has occured
 * while the bucket spinlock was being acquired.
 *
 * Related Work:
 * - Idea of cacheline-sized buckets with full hashes taken from:
 *   David, Guerraoui & Trigonakis, "Asynchronized Concurrency:
 *   The Secret to Scaling Concurrent Search Data Structures", ASPLOS'15.
 * - Why not RCU-based hash tables? They would allow us to get rid of the
 *   seqlock, but resizing would take forever since RCU read critical
 *   sections in QEMU take quite a long time.
 *   More info on relativistic hash tables:
 *   + Triplett, McKenney & Walpole, "Resizable, Scalable, Concurrent Hash
 *     Tables via Relativistic Programming", USENIX ATC'11.
 *   + Corbet, "Relativistic hash tables, part 1: Algorithms", @ lwn.net, 2014.
 *     https://lwn.net/Articles/612021/
 */
#include "qemu/osdep.h"
#include "qemu/qht.h"
#include "qemu/atomic.h"
//#include "qemu/rcu.h"

//#define QHT_DEBUG

/*
 * We want to avoid false sharing of cache lines. Most systems have 64-byte
 * cache lines so we go with it for simplicity.
 *
 * Note that systems with smaller cache lines will be fine (the struct is
 * almost 64-bytes); systems with larger cache lines might suffer from
 * some false sharing.
 */
#define QHT_BUCKET_ALIGN 64

/* define these to keep sizeof(qht_bucket) within QHT_BUCKET_ALIGN */
#if HOST_LONG_BITS == 32
#define QHT_BUCKET_ENTRIES 6
#else /* 64-bit */
#define QHT_BUCKET_ENTRIES 4
#endif

enum qht_iter_type {
    QHT_ITER_VOID,    /* do nothing; use retvoid */
    QHT_ITER_RM,      /* remove element if retbool returns true */
};

struct qht_iter {
    union {
        qht_iter_func_t retvoid;
        qht_iter_bool_func_t retbool;
    } f;
    enum qht_iter_type type;
};

/*
 * Note: reading partially-updated pointers in @pointers could lead to
 * segfaults. We thus access them with atomic_read/set; this guarantees
 * that the compiler makes all those accesses atomic. We also need the
 * volatile-like behavior in atomic_read, since otherwise the compiler
 * might refetch the pointer.
 * atomic_read's are of course not necessary when the bucket lock is held.
 *
 * If both ht->lock and b->lock are grabbed, ht->lock should always
 * be grabbed first.
 */
struct qht_bucket {
    uint32_t hashes[QHT_BUCKET_ENTRIES];
    void *pointers[QHT_BUCKET_ENTRIES];
    struct qht_bucket *next;
} QEMU_ALIGNED(QHT_BUCKET_ALIGN);

QEMU_BUILD_BUG_ON(sizeof(struct qht_bucket) > QHT_BUCKET_ALIGN);

/**
 * struct qht_map - structure to track an array of buckets
 * @rcu: used by RCU. Keep it as the top field in the struct to help valgrind
 *       find the whole struct.
 * @buckets: array of head buckets. It is constant once the map is created.
 * @n_buckets: number of head buckets. It is constant once the map is created.
 * @n_added_buckets: number of added (i.e. "non-head") buckets
 * @n_added_buckets_threshold: threshold to trigger an upward resize once the
 *                             number of added buckets surpasses it.
 *
 * Buckets are tracked in what we call a "map", i.e. this structure.
 */
struct qht_map {
    struct qht_bucket *buckets;
    size_t n_buckets;
    size_t n_added_buckets;
    size_t n_added_buckets_threshold;
};

/* trigger a resize when n_added_buckets > n_buckets / div */
#define QHT_NR_ADDED_BUCKETS_THRESHOLD_DIV 8

static void qht_do_resize_reset(struct uc_struct *uc, struct qht *ht, struct qht_map *new,
                                bool reset);
static void qht_grow_maybe(struct uc_struct *uc, struct qht *ht);

#define qht_debug_assert(X) do { (void)(X); } while (0)

static inline size_t qht_elems_to_buckets(size_t n_elems)
{
    return pow2ceil(n_elems / QHT_BUCKET_ENTRIES);
}

static inline void qht_head_init(struct qht_bucket *b)
{
    memset(b, 0, sizeof(*b));
}

static inline
struct qht_bucket *qht_map_to_bucket(const struct qht_map *map, uint32_t hash)
{
    return &map->buckets[hash & (map->n_buckets - 1)];
}

/*
 * Grab all bucket locks, and set @pmap after making sure the map isn't stale.
 *
 * Pairs with qht_map_unlock_buckets(), hence the pass-by-reference.
 *
 * Note: callers cannot have ht->lock held.
 */
static inline
void qht_map_lock_buckets__no_stale(struct qht *ht, struct qht_map **pmap)
{
    struct qht_map *map;
    map = ht->map;
    *pmap = map;
    return;
}

/*
 * Get a head bucket and lock it, making sure its parent map is not stale.
 * @pmap is filled with a pointer to the bucket's parent map.
 */
static inline
struct qht_bucket *qht_bucket_lock__no_stale(struct qht *ht, uint32_t hash,
                                             struct qht_map **pmap)
{
    struct qht_bucket *b;
    struct qht_map *map;

    map = ht->map;
    b = qht_map_to_bucket(map, hash);
    *pmap = map;
    return b;
}

static inline bool qht_map_needs_resize(const struct qht_map *map)
{
    return map->n_added_buckets > map->n_added_buckets_threshold;
}

static inline void qht_chain_destroy(const struct qht_bucket *head)
{
    struct qht_bucket *curr = head->next;
    struct qht_bucket *prev;

    while (curr) {
        prev = curr;
        curr = curr->next;
        qemu_vfree(prev);
    }
}

/* pass only an orphan map */
static void qht_map_destroy(struct qht_map *map)
{
    size_t i;

    for (i = 0; i < map->n_buckets; i++) {
        qht_chain_destroy(&map->buckets[i]);
    }
    qemu_vfree(map->buckets);
    g_free(map);
}

static struct qht_map *qht_map_create(size_t n_buckets)
{
    struct qht_map *map;
    size_t i;

    map = g_malloc(sizeof(*map));
    map->n_buckets = n_buckets;

    map->n_added_buckets = 0;
    map->n_added_buckets_threshold = n_buckets /
        QHT_NR_ADDED_BUCKETS_THRESHOLD_DIV;

    /* let tiny hash tables to at least add one non-head bucket */
    if (unlikely(map->n_added_buckets_threshold == 0)) {
        map->n_added_buckets_threshold = 1;
    }

    map->buckets = qemu_memalign(QHT_BUCKET_ALIGN,
                                 sizeof(*map->buckets) * n_buckets);
    for (i = 0; i < n_buckets; i++) {
        qht_head_init(&map->buckets[i]);
    }
    return map;
}

void qht_init(struct qht *ht, qht_cmp_func_t cmp, size_t n_elems,
              unsigned int mode)
{
    struct qht_map *map;
    size_t n_buckets = qht_elems_to_buckets(n_elems);

    g_assert(cmp);
    ht->cmp = cmp;
    ht->mode = mode;
    map = qht_map_create(n_buckets);
    ht->map = map;
}

/* call only when there are no readers/writers left */
void qht_destroy(struct qht *ht)
{
    qht_map_destroy(ht->map);
    memset(ht, 0, sizeof(*ht));
}

static void qht_bucket_reset__locked(struct qht_bucket *head)
{
    struct qht_bucket *b = head;
    int i;

    do {
        for (i = 0; i < QHT_BUCKET_ENTRIES; i++) {
            if (b->pointers[i] == NULL) {
                goto done;
            }
            b->hashes[i] = 0;
            b->pointers[i] = NULL;
        }
        b = b->next;
    } while (b);
 done:
    return;
}

/* call with all bucket locks held */
static void qht_map_reset__all_locked(struct qht_map *map)
{
    size_t i;

    for (i = 0; i < map->n_buckets; i++) {
        qht_bucket_reset__locked(&map->buckets[i]);
    }
}

void qht_reset(struct qht *ht)
{
    struct qht_map *map;

    qht_map_lock_buckets__no_stale(ht, &map);
    qht_map_reset__all_locked(map);
}

static inline void qht_do_resize(struct uc_struct *uc, struct qht *ht, struct qht_map *new)
{
    qht_do_resize_reset(uc, ht, new, false);
}

static inline void qht_do_resize_and_reset(struct uc_struct *uc, struct qht *ht, struct qht_map *new)
{
    qht_do_resize_reset(uc, ht, new, true);
}

bool qht_reset_size(struct uc_struct *uc, struct qht *ht, size_t n_elems)
{
    struct qht_map *new = NULL;
    struct qht_map *map;
    size_t n_buckets;

    n_buckets = qht_elems_to_buckets(n_elems);

    map = ht->map;
    if (n_buckets != map->n_buckets) {
        new = qht_map_create(n_buckets);
    }
    qht_do_resize_and_reset(uc, ht, new);

    return !!new;
}

static inline
void *qht_do_lookup(struct uc_struct *uc, const struct qht_bucket *head, qht_lookup_func_t func,
                    const void *userp, uint32_t hash)
{
    const struct qht_bucket *b = head;
    int i;

    do {
        for (i = 0; i < QHT_BUCKET_ENTRIES; i++) {
            if (b->hashes[i] == hash) {
                void *p = b->pointers[i];

                if (likely(p) && likely(func(uc, p, userp))) {
                    return p;
                }
            }
        }
        b = b->next;
    } while (b);

    return NULL;
}

void *qht_lookup_custom(struct uc_struct *uc, const struct qht *ht, const void *userp, uint32_t hash,
                        qht_lookup_func_t func)
{
    const struct qht_bucket *b;
    const struct qht_map *map;
    void *ret;

    map = ht->map;
    b = qht_map_to_bucket(map, hash);

    ret = qht_do_lookup(uc, b, func, userp, hash);
    return ret;
}

void *qht_lookup(struct uc_struct *uc, const struct qht *ht, const void *userp, uint32_t hash)
{
    return qht_lookup_custom(uc, ht, userp, hash, ht->cmp);
}

/*
 * call with head->lock held
 * @ht is const since it is only used for ht->cmp()
 */
static void *qht_insert__locked(struct uc_struct *uc, const struct qht *ht, struct qht_map *map,
                                struct qht_bucket *head, void *p, uint32_t hash,
                                bool *needs_resize)
{
    struct qht_bucket *b = head;
    struct qht_bucket *prev = NULL;
    struct qht_bucket *new = NULL;
    int i;

    do {
        for (i = 0; i < QHT_BUCKET_ENTRIES; i++) {
            if (b->pointers[i]) {
                if (unlikely(b->hashes[i] == hash &&
                             ht->cmp(uc, b->pointers[i], p))) {
                    return b->pointers[i];
                }
            } else {
                goto found;
            }
        }
        prev = b;
        b = b->next;
    } while (b);

    b = qemu_memalign(QHT_BUCKET_ALIGN, sizeof(*b));
    memset(b, 0, sizeof(*b));
    new = b;
    i = 0;
    map->n_added_buckets++;
    if (unlikely(qht_map_needs_resize(map)) && needs_resize) {
        *needs_resize = true;
    }

 found:
    /* found an empty key: acquire the seqlock and write */
    if (new) {
        prev->next = b;
    }
    b->hashes[i] = hash;
    b->pointers[i] = p;
    return NULL;
}

#ifdef _MSC_VER
static void qht_grow_maybe(struct uc_struct *uc, struct qht *ht)
#else
static __attribute__((noinline)) void qht_grow_maybe(struct uc_struct *uc, struct qht *ht)
#endif
{
    struct qht_map *map;

    map = ht->map;
    /* another thread might have just performed the resize we were after */
    if (qht_map_needs_resize(map)) {
        struct qht_map *new = qht_map_create(map->n_buckets * 2);

        qht_do_resize(uc, ht, new);
    }
}

bool qht_insert(struct uc_struct *uc, struct qht *ht, void *p, uint32_t hash, void **existing)
{
    struct qht_bucket *b;
    struct qht_map *map;
    bool needs_resize = false;
    void *prev;

    /* NULL pointers are not supported */
    qht_debug_assert(p);

    b = qht_bucket_lock__no_stale(ht, hash, &map);
    prev = qht_insert__locked(uc, ht, map, b, p, hash, &needs_resize);

    if (unlikely(needs_resize) && ht->mode & QHT_MODE_AUTO_RESIZE) {
        qht_grow_maybe(uc, ht);
    }
    if (likely(prev == NULL)) {
        return true;
    }
    if (existing) {
        *existing = prev;
    }
    return false;
}

static inline bool qht_entry_is_last(const struct qht_bucket *b, int pos)
{
    if (pos == QHT_BUCKET_ENTRIES - 1) {
        if (b->next == NULL) {
            return true;
        }
        return b->next->pointers[0] == NULL;
    }
    return b->pointers[pos + 1] == NULL;
}

static void
qht_entry_move(struct qht_bucket *to, int i, struct qht_bucket *from, int j)
{
    qht_debug_assert(!(to == from && i == j));
    qht_debug_assert(to->pointers[i]);
    qht_debug_assert(from->pointers[j]);

    to->hashes[i] = from->hashes[j];
    to->pointers[i] = from->pointers[j];
    from->hashes[j] = 0;
    from->pointers[j] = NULL;
}

/*
 * Find the last valid entry in @orig, and swap it with @orig[pos], which has
 * just been invalidated.
 */
static inline void qht_bucket_remove_entry(struct qht_bucket *orig, int pos)
{
    struct qht_bucket *b = orig;
    struct qht_bucket *prev = NULL;
    int i;

    if (qht_entry_is_last(orig, pos)) {
        orig->hashes[pos] = 0;
        orig->pointers[pos] = NULL;
        return;
    }
    do {
        for (i = 0; i < QHT_BUCKET_ENTRIES; i++) {
            if (b->pointers[i]) {
                continue;
            }
            if (i > 0) {
                qht_entry_move(orig, pos, b, i - 1);
                return;
            }
            qht_debug_assert(prev);
            qht_entry_move(orig, pos, prev, QHT_BUCKET_ENTRIES - 1);
            return;
        }
        prev = b;
        b = b->next;
    } while (b);
    /* no free entries other than orig[pos], so swap it with the last one */
    qht_entry_move(orig, pos, prev, QHT_BUCKET_ENTRIES - 1);
}

/* call with b->lock held */
static inline
bool qht_remove__locked(struct qht_bucket *head, const void *p, uint32_t hash)
{
    struct qht_bucket *b = head;
    int i;

    do {
        for (i = 0; i < QHT_BUCKET_ENTRIES; i++) {
            void *q = b->pointers[i];

            if (unlikely(q == NULL)) {
                return false;
            }
            if (q == p) {
                qht_debug_assert(b->hashes[i] == hash);
                qht_bucket_remove_entry(b, i);
                return true;
            }
        }
        b = b->next;
    } while (b);
    return false;
}

bool qht_remove(struct qht *ht, const void *p, uint32_t hash)
{
    struct qht_bucket *b;
    struct qht_map *map;
    bool ret;

    /* NULL pointers are not supported */
    qht_debug_assert(p);

    b = qht_bucket_lock__no_stale(ht, hash, &map);
    ret = qht_remove__locked(b, p, hash);
    return ret;
}

static inline void qht_bucket_iter(struct uc_struct *uc, struct qht_bucket *head,
                                   const struct qht_iter *iter, void *userp)
{
    struct qht_bucket *b = head;
    int i;

    do {
        for (i = 0; i < QHT_BUCKET_ENTRIES; i++) {
            if (b->pointers[i] == NULL) {
                return;
            }
            switch (iter->type) {
            case QHT_ITER_VOID:
                iter->f.retvoid(uc, b->pointers[i], b->hashes[i], userp);
                break;
            case QHT_ITER_RM:
                if (iter->f.retbool(b->pointers[i], b->hashes[i], userp)) {
                    /* replace i with the last valid element in the bucket */
                    qht_bucket_remove_entry(b, i);
                    /* reevaluate i, since it just got replaced */
                    i--;
                    continue;
                }
                break;
            default:
                g_assert_not_reached();
            }
        }
        b = b->next;
    } while (b);
}

/* call with all of the map's locks held */
static inline void qht_map_iter__all_locked(struct uc_struct *uc, struct qht_map *map,
                                            const struct qht_iter *iter,
                                            void *userp)
{
    size_t i;

    for (i = 0; i < map->n_buckets; i++) {
        qht_bucket_iter(uc, &map->buckets[i], iter, userp);
    }
}

static inline void
do_qht_iter(struct uc_struct *uc, struct qht *ht, const struct qht_iter *iter, void *userp)
{
    struct qht_map *map;

    map = ht->map;
    qht_map_iter__all_locked(uc, map, iter, userp);
}

void qht_iter(struct uc_struct *uc, struct qht *ht, qht_iter_func_t func, void *userp)
{
    const struct qht_iter iter = {
        .f.retvoid = func,
        .type = QHT_ITER_VOID,
    };

    do_qht_iter(uc, ht, &iter, userp);
}

void qht_iter_remove(struct uc_struct *uc, struct qht *ht, qht_iter_bool_func_t func, void *userp)
{
    const struct qht_iter iter = {
        .f.retbool = func,
        .type = QHT_ITER_RM,
    };

    do_qht_iter(uc, ht, &iter, userp);
}

struct qht_map_copy_data {
    struct qht *ht;
    struct qht_map *new;
};

static void qht_map_copy(struct uc_struct *uc, void *p, uint32_t hash, void *userp)
{
    struct qht_map_copy_data *data = userp;
    struct qht *ht = data->ht;
    struct qht_map *new = data->new;
    struct qht_bucket *b = qht_map_to_bucket(new, hash);

    /* no need to acquire b->lock because no thread has seen this map yet */
    qht_insert__locked(uc, ht, new, b, p, hash, NULL);
}

/*
 * Atomically perform a resize and/or reset.
 * Call with ht->lock held.
 */
static void qht_do_resize_reset(struct uc_struct *uc, struct qht *ht, struct qht_map *new, bool reset)
{
    struct qht_map *old;
    const struct qht_iter iter = {
        .f.retvoid = qht_map_copy,
        .type = QHT_ITER_VOID,
    };
    struct qht_map_copy_data data;

    old = ht->map;

    if (reset) {
        qht_map_reset__all_locked(old);
    }

    if (new == NULL) {
        return;
    }

    g_assert(new->n_buckets != old->n_buckets);
    data.ht = ht;
    data.new = new;
    qht_map_iter__all_locked(uc, old, &iter, &data);

    ht->map = new;
    qht_map_destroy(old);
}

bool qht_resize(struct uc_struct *uc, struct qht *ht, size_t n_elems)
{
    size_t n_buckets = qht_elems_to_buckets(n_elems);
    size_t ret = false;

    if (n_buckets != ht->map->n_buckets) {
        struct qht_map *new;

        new = qht_map_create(n_buckets);
        qht_do_resize(uc, ht, new);
        ret = true;
    }

    return ret;
}

/* pass @stats to qht_statistics_destroy() when done */
void qht_statistics_init(const struct qht *ht, struct qht_stats *stats)
{
    const struct qht_map *map;
    int i;

    map = ht->map;

    stats->used_head_buckets = 0;
    stats->entries = 0;
    qdist_init(&stats->chain);
    qdist_init(&stats->occupancy);
    /* bail out if the qht has not yet been initialized */
    if (unlikely(map == NULL)) {
        stats->head_buckets = 0;
        return;
    }
    stats->head_buckets = map->n_buckets;

    for (i = 0; i < map->n_buckets; i++) {
        const struct qht_bucket *head = &map->buckets[i];
        const struct qht_bucket *b;
        size_t buckets;
        size_t entries;
        int j;

        buckets = 0;
        entries = 0;
        b = head;
        do {
            for (j = 0; j < QHT_BUCKET_ENTRIES; j++) {
                if (b->pointers[j] == NULL) {
                    break;
                }
                entries++;
            }
            buckets++;
            b = b->next;
        } while (b);

        if (entries) {
            qdist_inc(&stats->chain, buckets);
            qdist_inc(&stats->occupancy,
                      (double)entries / QHT_BUCKET_ENTRIES / buckets);
            stats->used_head_buckets++;
            stats->entries += entries;
        } else {
            qdist_inc(&stats->occupancy, 0);
        }
    }
}

void qht_statistics_destroy(struct qht_stats *stats)
{
    qdist_destroy(&stats->occupancy);
    qdist_destroy(&stats->chain);
}
