const LRU = require('lru-cache');
const cache = LRU({
  max: 500,
  length: function (n, key) {
    return n * 2 + key.length
  },
  dispose: function (key, n) {
    n.close()
  },
  maxAge: 1000 * 60 * 60
});

/**
 * Set cache
 * @param key {string} - key for cache variable
 * @param val {any} - value for cache variable
 */
exports.set = (key, val) => cache.set(key, val);

/**
 * Get cache
 * @param key {string} - key for cache variable
 */
exports.get = key => cache.get(key);

exports.del = key => cache.del(key);

exports.has = key => cache.has(key);

/**
 * Reset all cache variables
 */
exports.reset = () => cache.reset();
