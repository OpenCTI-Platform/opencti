const assert = require('assert');
const querystring = require('querystring');
const http = require('http');
const https = require('https');
const { once } = require('events');
const { URL } = require('url');

const LRU = require('lru-cache');

const pkg = require('../../package.json');
const { RPError } = require('../errors');

const pick = require('./pick');
const { deep: defaultsDeep } = require('./defaults');
const { HTTP_OPTIONS } = require('./consts');

let DEFAULT_HTTP_OPTIONS;
const NQCHAR = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

const allowed = [
  'agent',
  'ca',
  'cert',
  'crl',
  'headers',
  'key',
  'lookup',
  'passphrase',
  'pfx',
  'timeout',
];

const setDefaults = (props, options) => {
  DEFAULT_HTTP_OPTIONS = defaultsDeep(
    {},
    props.length ? pick(options, ...props) : options,
    DEFAULT_HTTP_OPTIONS,
  );
};

setDefaults([], {
  headers: {
    'User-Agent': `${pkg.name}/${pkg.version} (${pkg.homepage})`,
    'Accept-Encoding': 'identity',
  },
  timeout: 3500,
});

function send(req, body, contentType) {
  if (contentType) {
    req.removeHeader('content-type');
    req.setHeader('content-type', contentType);
  }
  if (body) {
    req.removeHeader('content-length');
    req.setHeader('content-length', Buffer.byteLength(body));
    req.write(body);
  }
  req.end();
}

const nonces = new LRU({ max: 100 });

module.exports = async function request(options, { accessToken, mTLS = false, DPoP } = {}) {
  let url;
  try {
    url = new URL(options.url);
    delete options.url;
    assert(/^(https?:)$/.test(url.protocol));
  } catch (err) {
    throw new TypeError('only valid absolute URLs can be requested');
  }
  const optsFn = this[HTTP_OPTIONS];
  let opts = options;

  const nonceKey = `${url.origin}${url.pathname}`;
  if (DPoP && 'dpopProof' in this) {
    opts.headers = opts.headers || {};
    opts.headers.DPoP = await this.dpopProof(
      {
        htu: `${url.origin}${url.pathname}`,
        htm: options.method,
        nonce: nonces.get(nonceKey),
      },
      DPoP,
      accessToken,
    );
  }

  let userOptions;
  if (optsFn) {
    userOptions = pick(
      optsFn.call(this, url, defaultsDeep({}, opts, DEFAULT_HTTP_OPTIONS)),
      ...allowed,
    );
  }
  opts = defaultsDeep({}, userOptions, opts, DEFAULT_HTTP_OPTIONS);

  if (mTLS && !opts.pfx && !(opts.key && opts.cert)) {
    throw new TypeError('mutual-TLS certificate and key not set');
  }

  if (opts.searchParams) {
    for (const [key, value] of Object.entries(opts.searchParams)) {
      url.searchParams.delete(key);
      url.searchParams.set(key, value);
    }
  }

  let responseType;
  let form;
  let json;
  let body;
  ({ form, responseType, json, body, ...opts } = opts);

  for (const [key, value] of Object.entries(opts.headers || {})) {
    if (value === undefined) {
      delete opts.headers[key];
    }
  }

  let response;
  const req = (url.protocol === 'https:' ? https.request : http.request)(url.href, opts);
  return (async () => {
    if (json) {
      send(req, JSON.stringify(json), 'application/json');
    } else if (form) {
      send(req, querystring.stringify(form), 'application/x-www-form-urlencoded');
    } else if (body) {
      send(req, body);
    } else {
      send(req);
    }

    [response] = await Promise.race([once(req, 'response'), once(req, 'timeout')]);

    // timeout reached
    if (!response) {
      req.destroy();
      throw new RPError(`outgoing request timed out after ${opts.timeout}ms`);
    }

    const parts = [];

    for await (const part of response) {
      parts.push(part);
    }

    if (parts.length) {
      switch (responseType) {
        case 'json': {
          Object.defineProperty(response, 'body', {
            get() {
              let value = Buffer.concat(parts);
              try {
                value = JSON.parse(value);
              } catch (err) {
                Object.defineProperty(err, 'response', { value: response });
                throw err;
              } finally {
                Object.defineProperty(response, 'body', { value, configurable: true });
              }
              return value;
            },
            configurable: true,
          });
          break;
        }
        case undefined:
        case 'buffer': {
          Object.defineProperty(response, 'body', {
            get() {
              const value = Buffer.concat(parts);
              Object.defineProperty(response, 'body', { value, configurable: true });
              return value;
            },
            configurable: true,
          });
          break;
        }
        default:
          throw new TypeError('unsupported responseType request option');
      }
    }

    return response;
  })()
    .catch((err) => {
      if (response) Object.defineProperty(err, 'response', { value: response });
      throw err;
    })
    .finally(() => {
      const dpopNonce = response && response.headers['dpop-nonce'];
      if (dpopNonce && NQCHAR.test(dpopNonce)) {
        nonces.set(nonceKey, dpopNonce);
      }
    });
};

module.exports.setDefaults = setDefaults.bind(undefined, allowed);
