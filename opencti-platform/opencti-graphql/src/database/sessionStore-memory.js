import { LRUCache } from 'lru-cache';
import session from 'express-session';
import { UnsupportedError } from '../config/errors';

const ONE_DAY = 86400000;

// Time to live of a session, in milliseconds as expected by lru-cache.
// Without an explicit ttl option, the session cookie max age is used, then one day for session cookies (no max age).
// A ttl of zero or less means the session cookie already expired.
const getTTL = (options, sess, sid) => {
  if (typeof options.ttl === 'number') return options.ttl;
  if (typeof options.ttl === 'function') return options.ttl(options, sess, sid);
  if (options.ttl) {
    throw UnsupportedError('`options.ttl` must be a number or function.');
  }
  const maxAge = sess && sess.cookie ? sess.cookie.maxAge : null;
  return typeof maxAge === 'number' ? Math.floor(maxAge) : ONE_DAY;
};

const { Store } = session;

class SessionStoreMemory extends Store {
  constructor(options = {}) {
    super(options);
    this.options = {
      checkPeriod: options.checkPeriod,
      max: options.max || 1000,
      ttl: options.ttl,
    };
    // Same prefix and session decoration as the Redis store, as expected by the sessions management
    this.prefix = options.prefix == null ? 'sess:' : options.prefix;
    this.serializer = options.serializer || JSON;
    this.store = new LRUCache({ max: this.options.max });
    this.startInterval();
  }

  // region base commands
  get(sid, fn) {
    const data = this.store.get(sid);
    if (!data) return fn && fn();
    let err = null;
    let result;
    try {
      result = this.serializer.parse(data);
    } catch (er) {
      err = er;
    }
    return fn && fn(err, result);
  }

  // An expired session is removed rather than stored: a zero ttl would disable its expiration in lru-cache
  save(sid, sess) {
    const ttl = getTTL(this.options, sess, sid);
    if (!(ttl > 0)) {
      this.store.delete(sid);
      return;
    }
    this.store.set(sid, this.serializer.stringify(sess), { ttl });
  }

  set(sid, sess, fn) {
    try {
      this.save(sid, sess);
    } catch (err) {
      return fn && fn(err);
    }
    return fn && fn(null);
  }

  touch(sid, sess, fn) {
    let err = null;
    const data = this.store.get(sid);
    if (data !== undefined) {
      try {
        const s = this.serializer.parse(data);
        s.cookie = sess.cookie;
        this.save(sid, s);
      } catch (e) {
        err = e;
      }
    }
    return fn && fn(err);
  }

  // Calls back with the killed session in the same envelope as the Redis store, as expected by the sessions management
  destroy(sid, fn) {
    const data = this.store.get(sid);
    this.store.delete(sid);
    let err = null;
    let session;
    try {
      session = data === undefined ? undefined : this.serializer.parse(data);
    } catch (e) {
      err = e;
    }
    return fn && fn(err, { sessionId: this.prefix + sid, session });
  }

  ids(fn) {
    return fn && fn(null, [...this.store.keys()]);
  }

  all(fn) {
    let err = null;
    const result = [];
    try {
      this.store.forEach((val, key) => {
        result.push({
          ...this.serializer.parse(val),
          redis_key_id: this.prefix + key,
          redis_key_ttl: Math.round(this.store.getRemainingTTL(key) / 1000),
        });
      });
    } catch (e) {
      err = e;
    }
    return fn && fn(err, result);
  }

  clear(fn) {
    this.store.clear();
    return fn && fn(null);
  }

  length(fn) {
    return fn && fn(null, this.store.size);
  }
  // endregion

  startInterval() {
    const ms = this.options.checkPeriod;
    if (ms && typeof ms === 'number') {
      clearInterval(this._checkInterval);
      // proactively removes the expired sessions, lru-cache only drops them when they are read
      this._checkInterval = setInterval(() => this.prune(), Math.floor(ms));
      this._checkInterval.unref?.();
    }
  }

  stopInterval() {
    clearInterval(this._checkInterval);
  }

  prune() {
    this.store.purgeStale();
  }
}

export default SessionStoreMemory;
