const objectHash = require('object-hash');
const LRU = require('lru-cache');

const { RPError } = require('../errors');

const { assertIssuerConfiguration } = require('./assert');
const KeyStore = require('./keystore');
const { keystores } = require('./weak_cache');
const processResponse = require('./process_response');
const request = require('./request');

const inFlight = new WeakMap();
const caches = new WeakMap();
const lrus = (ctx) => {
  if (!caches.has(ctx)) {
    caches.set(ctx, new LRU({ max: 100 }));
  }
  return caches.get(ctx);
};

async function getKeyStore(reload = false) {
  assertIssuerConfiguration(this, 'jwks_uri');

  const keystore = keystores.get(this);
  const cache = lrus(this);

  if (reload || !keystore) {
    if (inFlight.has(this)) {
      return inFlight.get(this);
    }
    cache.reset();
    inFlight.set(
      this,
      (async () => {
        const response = await request
          .call(this, {
            method: 'GET',
            responseType: 'json',
            url: this.jwks_uri,
            headers: {
              Accept: 'application/json, application/jwk-set+json',
            },
          })
          .finally(() => {
            inFlight.delete(this);
          });
        const jwks = processResponse(response);

        const joseKeyStore = KeyStore.fromJWKS(jwks, { onlyPublic: true });
        cache.set('throttle', true, 60 * 1000);
        keystores.set(this, joseKeyStore);

        return joseKeyStore;
      })(),
    );

    return inFlight.get(this);
  }

  return keystore;
}

async function queryKeyStore({ kid, kty, alg, use }, { allowMulti = false } = {}) {
  const cache = lrus(this);

  const def = {
    kid,
    kty,
    alg,
    use,
  };

  const defHash = objectHash(def, {
    algorithm: 'sha256',
    ignoreUnknown: true,
    unorderedArrays: true,
    unorderedSets: true,
    respectType: false,
  });

  // refresh keystore on every unknown key but also only upto once every minute
  const freshJwksUri = cache.get(defHash) || cache.get('throttle');

  const keystore = await getKeyStore.call(this, !freshJwksUri);
  const keys = keystore.all(def);

  delete def.use;
  if (keys.length === 0) {
    throw new RPError({
      printf: ["no valid key found in issuer's jwks_uri for key parameters %j", def],
      jwks: keystore,
    });
  }

  if (!allowMulti && keys.length > 1 && !kid) {
    throw new RPError({
      printf: [
        "multiple matching keys found in issuer's jwks_uri for key parameters %j, kid must be provided in this case",
        def,
      ],
      jwks: keystore,
    });
  }

  cache.set(defHash, true);

  return keys;
}

module.exports.queryKeyStore = queryKeyStore;
module.exports.keystore = getKeyStore;
