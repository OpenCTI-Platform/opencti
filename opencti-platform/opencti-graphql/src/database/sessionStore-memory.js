import { LRUCache } from 'lru-cache';
import session from 'express-session';
import { UnsupportedError } from '../config/errors';

const ONE_DAY = 86400000;

const getTTL = (options, sess, sid) => {
  if (typeof options.ttl === 'number') return options.ttl;
  if (typeof options.ttl === 'function') return options.ttl(options, sess, sid);
  if (options.ttl) {
    throw UnsupportedError('`options.ttl` must be a number or function.');
  }
  const maxAge = sess && sess.cookie ? sess.cookie.maxAge : null;
  return typeof maxAge === 'number' ? Math.floor(maxAge) : ONE_DAY;
};

const prune = (store) => {
  store.forEach((value, key) => {
    store.get(key);
  });
};

const { Store } = session;

class SessionStoreMemory extends Store {
  constructor(options = {}) {
    super(options);

    this.options = {};
    this.options.checkPeriod = options.checkPeriod;
    this.options.max = options.max || 1000;
    this.options.ttl = options.ttl || 86400;
    this.options.dispose = options.dispose;
    this.options.stale = options.stale;
    this.options.noDisposeOnSet = options.noDisposeOnSet;

    this.serializer = options.serializer || JSON;
    this.store = new LRUCache(this.options);
    this.startInterval();
  }

  // region base commands
  get(sid, fn) {
    const { store } = this;
    const data = store.get(sid);
    if (!data) return fn();

    let err = null;
    let result;
    try {
      result = this.serializer.parse(data);
    } catch (er) {
      err = er;
    }
    return fn && fn(err, result);
  }

  set(sid, sess, fn) {
    const { store } = this;

    const ttl = getTTL(this.options, sess, sid);
    try {
      const jsess = this.serializer.stringify(sess);
      store.set(sid, jsess, ttl);
    } catch (err) {
      return fn && fn(err);
    }
    return fn && fn(null);
  }

  touch(sid, sess, fn) {
    const { store } = this;
    const ttl = getTTL(this.options, sess, sid);
    let err = null;
    if (store.get(sid) !== undefined) {
      try {
        const s = this.serializer.parse(store.get(sid));
        s.cookie = sess.cookie;
        store.set(sid, this.serializer.stringify(s), ttl);
      } catch (e) {
        err = e;
      }
    }
    return fn && fn(err);
  }

  destroy(sid, fn) {
    const { store } = this;
    store.get(sid, (error, data) => {
      store.delete(sid);
      return fn && fn(error, data);
    });
  }

  ids(fn) {
    const { store } = this;
    const Ids = store.keys();
    return fn && fn(null, Ids);
  }

  all(fn) {
    const { store } = this;
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const self = this;
    let err = null;
    const result = {};
    try {
      store.forEach((val, key) => {
        result[key] = self.serializer.parse(val);
      });
    } catch (e) {
      err = e;
    }
    return fn && fn(err, result);
  }

  clear(fn) {
    const { store } = this;
    store.reset();
    return fn && fn(null);
  }

  length(fn) {
    const { store } = this;
    return fn && fn(null, store.itemCount);
  }
  // endregion

  startInterval() {
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const self = this;
    const ms = this.options.checkPeriod;
    if (ms && typeof ms === 'number') {
      clearInterval(this._checkInterval);
      this._checkInterval = setInterval(() => {
        prune(self.store); // iterates over the entire cache proactively pruning old entries
      }, Math.floor(ms));
    }
  }

  stopInterval() {
    clearInterval(this._checkInterval);
  }

  prune() {
    prune(this.store);
  }
}

export default SessionStoreMemory;
