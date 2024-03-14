const LRU = require('lru-cache');

module.exports = new LRU({ max: 100 });
