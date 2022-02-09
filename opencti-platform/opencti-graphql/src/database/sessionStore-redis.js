import session from 'express-session';
import LRU from 'lru-cache';
import AsyncLock from 'async-lock';

const { Store } = session;

const noop = () => {};

class RedisStore extends Store {
  constructor(client, options = {}) {
    super(options);
    this.client = client;
    this.prefix = options.prefix == null ? 'sess:' : options.prefix;
    this.scanCount = Number(options.scanCount) || 100;
    this.serializer = options.serializer || JSON;
    this.ttl = options.ttl || 86400; // One day in seconds.
    this.cache = new LRU({ ttl: 1000, max: 1000 }); // Force refresh the session every sec
    this.touchCache = new LRU({ ttl: 120000, max: 1000 }); // Touch the session every 2 minutes
    this.locker = new AsyncLock();
  }

  // region base commands
  get(sid, cb = noop) {
    const key = this.prefix + sid;
    const { cache } = this;
    const sessionFetcher = (done) => {
      const cachedSession = cache.get(`get-${key}`);
      if (cachedSession) {
        return done(null, cachedSession);
      }
      return this.client.get(key, (err, data) => {
        if (err) return done(err);
        if (!data) return done();
        const result = this.serializer.parse(data);
        cache.set(`get-${key}`, result);
        return done(null, result);
      });
    };
    this.locker.acquire(key, sessionFetcher, (error, result) => {
      return cb(error, result);
    });
  }

  set(sid, sess, cb = noop) {
    const key = this.prefix + sid;
    const args = [key];
    const { cache } = this;
    let value;
    try {
      value = this.serializer.stringify(sess);
    } catch (er) {
      return cb(er);
    }
    args.push(this._getTTL(sess));
    args.push(value);
    const sessionSetter = (done) => {
      return this.client.setex(args, (err, data) => {
        cache.set(`get-${key}`, sess);
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
      const cachedTouch = touchCache.get(`touch-${key}`);
      if (cachedTouch) {
        return done();
      }
      return this.client.expire(key, this._getTTL(sess), (err, ret) => {
        if (err) return done(err);
        if (ret !== 1) return done(null, 'EXPIRED');
        this.touchCache.set(`touch-${key}`, true);
        return done(null, 'OK');
      });
    };
    this.locker.acquire(key, sessionExtender, (error, result) => {
      return cb(error, result);
    });
  }

  destroy(sid, cb = noop) {
    const key = this.prefix + sid;
    this.client.del(key, cb);
  }

  ids(cb = noop) {
    const prefixLen = this.prefix.length;

    this._getAllKeys((err, keys) => {
      if (err) return cb(err);
      const mappedKeys = keys.map((key) => key.substr(prefixLen));
      return cb(null, mappedKeys);
    });
  }

  all(cb = noop) {
    const prefixLen = this.prefix.length;

    this._getAllKeys((err, keys) => {
      if (err) return cb(err);
      if (keys.length === 0) return cb(null, []);

      return this.client.mget(keys, (mgetErr, sessions) => {
        if (mgetErr) return cb(mgetErr);

        let result;
        try {
          result = sessions.reduce((accum, data, index) => {
            if (!data) return accum;
            const parsedData = this.serializer.parse(data);
            parsedData.id = keys[index].substr(prefixLen);
            accum.push(parsedData);
            return accum;
          }, []);
        } catch (e) {
          return cb(e);
        }
        return cb(err, result);
      });
    });
  }

  clear(cb = noop) {
    this._getAllKeys((err, keys) => {
      if (err) return cb(err);
      return this.client.del(keys, cb);
    });
  }

  length(cb = noop) {
    this._getAllKeys((err, keys) => {
      if (err) return cb(err);
      return cb(null, keys.length);
    });
  }

  expiration(sid, cb = noop) {
    const key = this.prefix + sid;
    this.client.ttl(key, cb);
  }
  // endregion

  _getTTL(sess) {
    let ttl;
    if (sess && sess.cookie && sess.cookie.expires) {
      const ms = Number(new Date(sess.cookie.expires)) - Date.now();
      ttl = Math.ceil(ms / 1000);
    } else {
      ttl = this.ttl;
    }
    return ttl;
  }

  _getAllKeys(cb = noop) {
    const pattern = `${this.prefix}*`;
    this._scanKeys({}, 0, pattern, this.scanCount, cb);
  }

  _scanKeys(keys, cursor, pattern, count, cb = noop) {
    const args = [cursor, 'match', pattern, 'count', count];
    this.client.scan(args, (err, data) => {
      if (err) return cb(err);

      const [nextCursorId, scanKeys] = data;
      // eslint-disable-next-line no-restricted-syntax
      for (const key of scanKeys) {
        // eslint-disable-next-line no-param-reassign
        keys[key] = true;
      }

      // This can be a string or a number. We check both.
      if (Number(nextCursorId) !== 0) {
        return this._scanKeys(keys, nextCursorId, pattern, count, cb);
      }

      return cb(null, Object.keys(keys));
    });
  }
}

export default RedisStore;
