const jose = require('jose');

const clone = require('./deep_clone');
const isPlainObject = require('./is_plain_object');

const internal = Symbol();

const keyscore = (key, { alg, use }) => {
  let score = 0;

  if (alg && key.alg) {
    score++;
  }

  if (use && key.use) {
    score++;
  }

  return score;
};

function getKtyFromAlg(alg) {
  switch (typeof alg === 'string' && alg.slice(0, 2)) {
    case 'RS':
    case 'PS':
      return 'RSA';
    case 'ES':
      return 'EC';
    case 'Ed':
      return 'OKP';
    default:
      return undefined;
  }
}

function getAlgorithms(use, alg, kty, crv) {
  // Ed25519, Ed448, and secp256k1 always have "alg"
  // OKP always has "use"
  if (alg) {
    return new Set([alg]);
  }

  switch (kty) {
    case 'EC': {
      let algs = [];

      if (use === 'enc' || use === undefined) {
        algs = algs.concat(['ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW']);
      }

      if (use === 'sig' || use === undefined) {
        switch (crv) {
          case 'P-256':
          case 'P-384':
            algs = algs.concat([`ES${crv.slice(-3)}`]);
            break;
          case 'P-521':
            algs = algs.concat(['ES512']);
            break;
          case 'secp256k1':
            if (jose.cryptoRuntime === 'node:crypto') {
              algs = algs.concat(['ES256K']);
            }
            break;
        }
      }

      return new Set(algs);
    }
    case 'OKP': {
      return new Set(['ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW']);
    }
    case 'RSA': {
      let algs = [];

      if (use === 'enc' || use === undefined) {
        algs = algs.concat(['RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512']);
        if (jose.cryptoRuntime === 'node:crypto') {
          algs = algs.concat(['RSA1_5']);
        }
      }

      if (use === 'sig' || use === undefined) {
        algs = algs.concat(['PS256', 'PS384', 'PS512', 'RS256', 'RS384', 'RS512']);
      }

      return new Set(algs);
    }
    default:
      throw new Error('unreachable');
  }
}

module.exports = class KeyStore {
  #keys;

  constructor(i, keys) {
    if (i !== internal) throw new Error('invalid constructor call');
    this.#keys = keys;
  }

  toJWKS() {
    return {
      keys: this.map(({ jwk: { d, p, q, dp, dq, qi, ...jwk } }) => jwk),
    };
  }

  all({ alg, kid, use } = {}) {
    if (!use || !alg) {
      throw new Error();
    }

    const kty = getKtyFromAlg(alg);

    const search = { alg, use };
    return this.filter((key) => {
      let candidate = true;

      if (candidate && kty !== undefined && key.jwk.kty !== kty) {
        candidate = false;
      }

      if (candidate && kid !== undefined && key.jwk.kid !== kid) {
        candidate = false;
      }

      if (candidate && use !== undefined && key.jwk.use !== undefined && key.jwk.use !== use) {
        candidate = false;
      }

      if (candidate && key.jwk.alg && key.jwk.alg !== alg) {
        candidate = false;
      } else if (!key.algorithms.has(alg)) {
        candidate = false;
      }

      return candidate;
    }).sort((first, second) => keyscore(second, search) - keyscore(first, search));
  }

  get(...args) {
    return this.all(...args)[0];
  }

  static async fromJWKS(jwks, { onlyPublic = false, onlyPrivate = false } = {}) {
    if (
      !isPlainObject(jwks) ||
      !Array.isArray(jwks.keys) ||
      jwks.keys.some((k) => !isPlainObject(k) || !('kty' in k))
    ) {
      throw new TypeError('jwks must be a JSON Web Key Set formatted object');
    }

    const keys = [];

    for (let jwk of jwks.keys) {
      jwk = clone(jwk);
      const { kty, kid, crv } = jwk;

      let { alg, use } = jwk;

      if (typeof kty !== 'string' || !kty) {
        continue;
      }

      if (use !== undefined && use !== 'sig' && use !== 'enc') {
        continue;
      }

      if (typeof alg !== 'string' && alg !== undefined) {
        continue;
      }

      if (typeof kid !== 'string' && kid !== undefined) {
        continue;
      }

      if (kty === 'EC' && use === 'sig') {
        switch (crv) {
          case 'P-256':
            alg = 'ES256';
            break;
          case 'P-384':
            alg = 'ES384';
            break;
          case 'P-521':
            alg = 'ES512';
            break;
          default:
            break;
        }
      }

      if (crv === 'secp256k1') {
        use = 'sig';
        alg = 'ES256K';
      }

      if (kty === 'OKP') {
        switch (crv) {
          case 'Ed25519':
          case 'Ed448':
            use = 'sig';
            alg = 'EdDSA';
            break;
          case 'X25519':
          case 'X448':
            use = 'enc';
            break;
          default:
            break;
        }
      }

      if (alg && !use) {
        switch (true) {
          case alg.startsWith('ECDH'):
            use = 'enc';
            break;
          case alg.startsWith('RSA'):
            use = 'enc';
            break;
          default:
            break;
        }
      }

      if (onlyPrivate && (jwk.kty === 'oct' || !jwk.d)) {
        throw new Error('jwks must only contain private keys');
      }

      if (onlyPublic && (jwk.d || jwk.k)) {
        continue;
      }

      keys.push({
        jwk: { ...jwk, alg, use },
        async keyObject(alg) {
          if (this[alg]) {
            return this[alg];
          }

          const keyObject = await jose.importJWK(this.jwk, alg);
          this[alg] = keyObject;
          return keyObject;
        },
        get algorithms() {
          Object.defineProperty(this, 'algorithms', {
            value: getAlgorithms(this.jwk.use, this.jwk.alg, this.jwk.kty, this.jwk.crv),
            enumerable: true,
            configurable: false,
          });
          return this.algorithms;
        },
      });
    }

    return new this(internal, keys);
  }

  filter(...args) {
    return this.#keys.filter(...args);
  }

  find(...args) {
    return this.#keys.find(...args);
  }

  every(...args) {
    return this.#keys.every(...args);
  }

  some(...args) {
    return this.#keys.some(...args);
  }

  map(...args) {
    return this.#keys.map(...args);
  }

  forEach(...args) {
    return this.#keys.forEach(...args);
  }

  reduce(...args) {
    return this.#keys.reduce(...args);
  }

  sort(...args) {
    return this.#keys.sort(...args);
  }

  *[Symbol.iterator]() {
    for (const key of this.#keys) {
      yield key;
    }
  }
};
