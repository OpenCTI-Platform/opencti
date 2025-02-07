/* eslint-disable class-methods-use-this */
import session from 'express-session';
import { LRUCache } from 'lru-cache';
import AsyncLock from 'async-lock';
import { clearSessions, extendSession, getSession, getSessionKeys, getSessions, getSessionTtl, killSession, setSession } from './redis';
import { logApp } from '../config/conf';

const { Store } = session;

const noop = () => {};

class RedisStore extends Store {
  constructor(options = {}) {
    super(options);
    this.ttl = options.ttl / 1000;
    this.prefix = options.prefix == null ? 'sess:' : options.prefix;
    this.scanCount = Number(options.scanCount) || 100;
    this.serializer = options.serializer || JSON;
    this.cache = new LRUCache({ ttl: 2500, max: 1000 }); // Force refresh the session every 2.5 sec
    this.touchCache = new LRUCache({ ttl: 120000, max: 1000 }); // Touch the session every 2 minutes
    this.locker = new AsyncLock();
  }

  get(sid, cb = noop) {
    const key = this.prefix + sid;
    const { cache } = this;
    const sessionFetcher = (done) => {
      const cachedSession = cache.get(`get-${key}`);
      if (cachedSession) {
        return done(null, cachedSession);
      }
      return getSession(key).then((data) => {
        if (!data) return done();
        cache.set(`get-${key}`, data);
        return done(null, data);
      });
    };
    this.locker.acquire(key, sessionFetcher, (error, result) => {
      return cb(error, result);
    });
  }

  set(sid, sess, cb = noop) {
    const key = this.prefix + sid;
    const { cache } = this;
    const sessionSetter = (done) => {
      return setSession(key, sess, this.ttl).then((data) => {
        cache.set(`get-${key}`, data);
        return done(null, data);
      });
    };
    return this.locker.acquire(key, sessionSetter, (error, result) => {
      return cb(error, result);
    });
  }

  touch(sid, sess, cb = noop) {
    const key = this.prefix + sid;
    const { touchCache } = this;
    const sessionExtender = (done) => {
      const cachedTouch = touchCache.has(`touch-${key}`);
      if (cachedTouch) {
        return done(null, 'OK');
      }
      return extendSession(key, this.ttl).then(((ret) => {
        if (ret !== 1) return done(null, 'EXPIRED');
        touchCache.set(`touch-${key}`, 'touched');
        return done(null, 'OK');
      }));
    };
    this.locker.acquire(key, sessionExtender, (error, result) => {
      return cb(error, result);
    });
  }

  destroy(sid, cb = noop) {
    const key = this.prefix + sid;
    return killSession(key).then((data) => cb(null, data));
  }

  all(cb = noop) {
    return getSessions().then((sessions) => {
      return cb(null, sessions);
    });
  }

  clear(cb = noop) {
    return clearSessions().then(() => cb(null, true));
  }

  length(cb = noop) {
    this._getAllKeys((err, keys) => {
      if (err) return cb(err);
      return cb(null, keys.length);
    }).catch((err) => logApp.error('[REDIS] Error on get all keys', { cause: err }));
  }

  expiration(sid, cb = noop) {
    const key = this.prefix + sid;
    getSessionTtl(key).then((ttl) => cb(null, ttl)).catch((err) => logApp.error('[REDIS] Error on get session TTL', { cause: err }));
  }

  _getAllKeys(cb = noop) {
    return getSessionKeys().then((keys) => {
      return cb(null, keys);
    });
  }
}

export default RedisStore;
