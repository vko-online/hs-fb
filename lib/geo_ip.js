const geoip = require('geoip-lite');

/**
 * Get geo location
 * Return { range, country, region, city, ll }
 * @param ip {string} - string representing IPv4 address
 */
exports.get = (ip) => geoip.lookup(ip);
