/* ugh, an ugly approximation to std::map (or rather, std::hash_map).
 * this is what happens when I use C rather than C++...
 */

#ifndef __MYSOCK_HASH_H__
#define __MYSOCK_HASH_H__

#include <stdlib.h>
#include <assert.h>
#include "mysock.h"


/* these macros do not handle thread safety; the calling code should
 * lock/unlock the hash table as needed.
 *
 * HASH_TABLE_DECLARE and HASH_TABLE_DECLARE_EXTENDED must be invoked in
 * the global namespace, before any use of the hash table.  HASH_INSERT,
 * HASH_DELETE, and HASH_LOOKUP perform the usual insertion, delete, and
 * lookup operations, using chaining for conflict resolution.  data items
 * are copied into the hash table; this is a shallow copy for pointers.
 * insertion does not check for duplicates; HASH_LOOKUP is valid for a key
 * only if HASH_ENTRY_EXISTS returns true for the corresponding key.
 * HASH_LOOKUP_PTR is a special version of HASH_LOOKUP for the case where
 * the data type stored in the hash is a pointer; it permits queries
 * without checking for key existence first, and returns NULL on a key's
 * absence from the table.  (if the key exists, it behaves identically to
 * HASH_LOOKUP).
 *
 * example usage, to map uint16_t -> mysock_context_t * using a hash
 * function unsigned int port_hash(uint16_t key, unsigned int table_size):
 *
 * static __inline bool_t key_equal(uint16_t a, uint16_t b)
 *   { return (a) == (b); }
 * static __inline unsigned int port_hash(uint16_t key, unsigned int size)
 *   { return (key) % (size); }
 *
 * HASH_TABLE_DECLARE_EXTENDED(port_table, uint16_t, mysock_context_t *,
 *                             port_hash, key_equal, 1024);
 *
 * --or (simpler)--
 * HASH_TABLE_DECLARE(port_table, uint16_t, mysock_context_t *, 1024);
 *
 * ...
 * uint16_t new_port;
 * mysock_context_t *new_ctx;
 * ...
 * HASH_INSERT(port_table, new_port, new_ctx);
 * assert(HASH_ENTRY_EXISTS(port_table, new_port));
 * assert(HASH_LOOKUP(port_table, new_port) == new_ctx);
 * HASH_DELETE(port_table, new_port);
 * assert(!HASH_ENTRY_EXISTS(port_table, new_port));
 * assert(!HASH_LOOKUP_PTR(port_table, new_port));
 *
 */

#define HASH_TABLE_DECLARE_EXTENDED(tbl,keytype,datatype,hashfn,keyequal,size)\
typedef struct tbl##_entry \
{ \
    keytype             key; \
    datatype            data; \
    struct tbl##_entry *next; \
} __##tbl##_entry_t; \
static __##tbl##_entry_t *tbl[size]; \
\
static __##tbl##_entry_t *_hash_get_entry_##tbl(keytype key) \
{ \
    __##tbl##_entry_t *e; \
    unsigned int ndx; \
    \
    ndx = hashfn(key, size); \
    assert(ndx < size); \
    \
    for (e = tbl[ndx]; e && !keyequal(e->key, key); e = e->next) ; \
    return (e && keyequal(e->key, key)) ? e : NULL; \
} \
\
static void _hash_insert_##tbl(keytype key, datatype data) \
{ \
    unsigned int ndx; \
    __##tbl##_entry_t *old_head; \
    \
    ndx = hashfn(key, size); \
    assert(ndx < size); \
    old_head = tbl[ndx]; \
    \
    tbl[ndx] = (__##tbl##_entry_t *) malloc(sizeof(__##tbl##_entry_t)); \
    assert(tbl[ndx]); \
    \
    tbl[ndx]->key  = key; \
    tbl[ndx]->data = data; \
    tbl[ndx]->next = old_head; \
    \
    assert(_hash_get_entry_##tbl(key) == tbl[ndx]); \
} \
\
static datatype _hash_lookup_##tbl(keytype key) \
{ \
    __##tbl##_entry_t *e = _hash_get_entry_##tbl(key); \
    assert(e); \
    return e->data; \
} \
\
static datatype _hash_lookup_ptr_##tbl(keytype key) \
{ \
    __##tbl##_entry_t *e = _hash_get_entry_##tbl(key); \
    return e ? e->data : NULL; \
} \
\
static bool_t _hash_entry_exists_##tbl(keytype key) \
{ \
    __##tbl##_entry_t *e = _hash_get_entry_##tbl(key); \
    return (e != NULL); \
} \
\
static void _hash_set_entry_##tbl(keytype key, datatype data) \
{ \
    __##tbl##_entry_t *e = _hash_get_entry_##tbl(key); \
    if (e != NULL) \
        e->data = data; \
    else \
        _hash_insert_##tbl(key, data); \
} \
\
static void _hash_delete_##tbl(keytype key) \
{ \
    __##tbl##_entry_t *prev = 0, *e; \
    unsigned int ndx; \
    \
    ndx = hashfn(key, size); \
    assert(ndx < size); \
    \
    for (e = tbl[ndx]; e; e = e->next) \
    { \
        if (keyequal(e->key, key)) \
        { \
            *((e == tbl[ndx]) ? &tbl[ndx] : &prev->next) = e->next; \
            break; \
        } \
        prev = e; \
    } \
    \
    free(e); \
    assert(!_hash_get_entry_##tbl(key)); \
}


#define HASH_INSERT(tbl,key,entry)      _hash_insert_##tbl(key, entry)
#define HASH_DELETE(tbl,key)            _hash_delete_##tbl(key)
#define HASH_ENTRY_EXISTS(tbl,key)      _hash_entry_exists_##tbl(key)
#define HASH_SET_ENTRY(tbl,key,entry)   _hash_set_entry_##tbl(key, entry)
#define HASH_LOOKUP(tbl,key)            _hash_lookup_##tbl(key)
#define HASH_LOOKUP_PTR(tbl,key)        _hash_lookup_ptr_##tbl(key)

#define HASH_DEFAULT_KEY_EQUALS(a,b)    ((a) == (b))
#define HASH_DEFAULT_HASH_FN(key,size)  ((key) % (size))

#define HASH_TABLE_DECLARE(tbl,keytype,datatype,size) \
    HASH_TABLE_DECLARE_EXTENDED(tbl, keytype, datatype, \
                                HASH_DEFAULT_HASH_FN, \
                                HASH_DEFAULT_KEY_EQUALS,size)


#endif  /* __MYSOCK_HASH_H__ */

