#ifndef CACHE_H
#define CACHE_H

/** Writes cache
 * 
 * The cache is associative with each entry corresponding to a write in an
 * address location of length 1..32 bytes. The simple CACHE_ENTRY function is
 * used to reduce the address to a cache index. As multiple address can map to
 * the same slot, a check is made to ensure that the write corresponds to the
 * same address, and that its length is equal or smaller than the one specified
 * by the cache entry.
 */

//! Cache capacity in entries
#define CACHE_BUCKETS	0x1000
//! Binary mask for getting index of address in cache
#define CACHE_MASK	0xfff 
//! Macro for retrieving the index of an address in the cache
#define CACHE_ENTRY(cache, addr) ((cache) + (((addr) >> 2) & CACHE_MASK))
//#define CACHE_ENTRY(cache, addr) ((cache) + (uint8_t)((addr) >> 2))


typedef struct cache_entry_struct {
	ADDRINT addr;
	UINT8 len;
} cache_entry_t;

//#define CACHE_DISABLE

#ifdef CACHE_DISABLE
# define WRITESCACHE_UPDATE(cachep, address, length) do { } while (0)
# define WritesCacheCheckB(cachep, address)	1
# define WritesCacheCheckW(cachep, address)	1
# define WritesCacheCheckL(cachep, address)	1
# define WritesCacheCheckQ(cachep, address)	1
# define WritesCacheCheckDQ(cachep, address)	1
# define WritesCacheCheckQQ(cachep, address)	1
#else

/**
 * Update cache entry
 */
#define WRITESCACHE_UPDATE(cachep, address, length) \
do {\
	cache_entry_t *entry;\
	entry = CACHE_ENTRY(cachep, address);\
	entry->addr = (address);\
	entry->len = (length);\
} while (0)


/**
 * Check if a byte address is in the cache.
 *
 * @param cache Pointer to cache
 * @param addr Address to check
 * @return 0 on cache hit, and non-zero on miss
 */
static inline ADDRINT WritesCacheCheckB(cache_entry_t *cache, ADDRINT addr)
{
	cache_entry_t *ce;

	ce = CACHE_ENTRY(cache, addr);
	return (ce->addr ^ addr); // Addresses do not match -> miss
}

/**
 * Check if a byte address is in the cache.
 *
 * @param cache Pointer to cache
 * @param addr Address to check
 * @return 0 on cache hit, and non-zero on miss
 */
static inline ADDRINT WritesCacheCheckW(cache_entry_t *cache, ADDRINT addr)
{
	cache_entry_t *ce;

	ce = CACHE_ENTRY(cache, addr);
	return (ce->addr ^ addr) | // Addresses do not match -> miss
		(ce->len & 0x1); // Length smaller than 2 -> miss
}

/**
 * Check if a byte address is in the cache.
 *
 * @param cache Pointer to cache
 * @param addr Address to check
 * @return 0 on cache hit, and non-zero on miss
 */
static inline ADDRINT WritesCacheCheckL(cache_entry_t *cache, ADDRINT addr)
{
	cache_entry_t *ce;

	ce = CACHE_ENTRY(cache, addr);
	return (ce->addr ^ addr) | // Addresses do not match -> miss
		(ce->len & 0x3); // Length smaller than 4 -> miss
}

/**
 * Check if a byte address is in the cache.
 *
 * @param cache Pointer to cache
 * @param addr Address to check
 * @return 0 on cache hit, and non-zero on miss
 */
static inline ADDRINT WritesCacheCheckQ(cache_entry_t *cache, ADDRINT addr)
{
	cache_entry_t *ce;

	ce = CACHE_ENTRY(cache, addr);
	return (ce->addr ^ addr) | // Addresses do not match -> miss
		(ce->len & 0x7); // Length smaller than 8 -> miss
}

/**
 * Check if a byte address is in the cache.
 *
 * @param cache Pointer to cache
 * @param addr Address to check
 * @return 0 on cache hit, and non-zero on miss
 */
static inline ADDRINT WritesCacheCheckDQ(cache_entry_t *cache, ADDRINT addr)
{
	cache_entry_t *ce;

	ce = CACHE_ENTRY(cache, addr);
	return (ce->addr ^ addr) | // Addresses do not match -> miss
		(ce->len & 0xF); // Length smaller than 16 -> miss
}

/**
 * Check if a byte address is in the cache.
 *
 * @param cache Pointer to cache
 * @param addr Address to check
 * @return 0 on cache hit, and non-zero on miss
 */
static inline ADDRINT WritesCacheCheckQQ(cache_entry_t *cache, ADDRINT addr)
{
	cache_entry_t *ce;

	ce = CACHE_ENTRY(cache, addr);
	return (ce->addr ^ addr) | // Addresses do not match -> miss
		(ce->len & 0x1F); // Length smaller than 16 -> miss
}
#endif // !CACHE_DISABLE

#endif
