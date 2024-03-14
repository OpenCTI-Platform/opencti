const { inspect } = require('util');
const url = require('url');

const { RPError } = require('./errors');
const getClient = require('./client');
const registry = require('./issuer_registry');
const processResponse = require('./helpers/process_response');
const webfingerNormalize = require('./helpers/webfinger_normalize');
const request = require('./helpers/request');
const clone = require('./helpers/deep_clone');
const { keystore } = require('./helpers/issuer');

const AAD_MULTITENANT_DISCOVERY = [
  'https://login.microsoftonline.com/common/.well-known/openid-configuration',
  'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
  'https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration',
  'https://login.microsoftonline.com/consumers/v2.0/.well-known/openid-configuration',
];
const AAD_MULTITENANT = Symbol();
const ISSUER_DEFAULTS = {
  claim_types_supported: ['normal'],
  claims_parameter_supported: false,
  grant_types_supported: ['authorization_code', 'implicit'],
  request_parameter_supported: false,
  request_uri_parameter_supported: true,
  require_request_uri_registration: false,
  response_modes_supported: ['query', 'fragment'],
  token_endpoint_auth_methods_supported: ['client_secret_basic'],
};

class Issuer {
  #metadata;
  constructor(meta = {}) {
    const aadIssValidation = meta[AAD_MULTITENANT];
    delete meta[AAD_MULTITENANT];
    ['introspection', 'revocation'].forEach((endpoint) => {
      // if intro/revocation endpoint auth specific meta is missing use the token ones if they
      // are defined
      if (
        meta[`${endpoint}_endpoint`] &&
        meta[`${endpoint}_endpoint_auth_methods_supported`] === undefined &&
        meta[`${endpoint}_endpoint_auth_signing_alg_values_supported`] === undefined
      ) {
        if (meta.token_endpoint_auth_methods_supported) {
          meta[`${endpoint}_endpoint_auth_methods_supported`] =
            meta.token_endpoint_auth_methods_supported;
        }
        if (meta.token_endpoint_auth_signing_alg_values_supported) {
          meta[`${endpoint}_endpoint_auth_signing_alg_values_supported`] =
            meta.token_endpoint_auth_signing_alg_values_supported;
        }
      }
    });

    this.#metadata = new Map();

    Object.entries(meta).forEach(([key, value]) => {
      this.#metadata.set(key, value);
      if (!this[key]) {
        Object.defineProperty(this, key, {
          get() {
            return this.#metadata.get(key);
          },
          enumerable: true,
        });
      }
    });

    registry.set(this.issuer, this);

    const Client = getClient(this, aadIssValidation);

    Object.defineProperties(this, {
      Client: { value: Client, enumerable: true },
      FAPI1Client: { value: class FAPI1Client extends Client {}, enumerable: true },
    });
  }

  get metadata() {
    return clone(Object.fromEntries(this.#metadata.entries()));
  }

  static async webfinger(input) {
    const resource = webfingerNormalize(input);
    const { host } = url.parse(resource);
    const webfingerUrl = `https://${host}/.well-known/webfinger`;

    const response = await request.call(this, {
      method: 'GET',
      url: webfingerUrl,
      responseType: 'json',
      searchParams: { resource, rel: 'http://openid.net/specs/connect/1.0/issuer' },
      headers: {
        Accept: 'application/json',
      },
    });
    const body = processResponse(response);

    const location =
      Array.isArray(body.links) &&
      body.links.find(
        (link) =>
          typeof link === 'object' &&
          link.rel === 'http://openid.net/specs/connect/1.0/issuer' &&
          link.href,
      );

    if (!location) {
      throw new RPError({
        message: 'no issuer found in webfinger response',
        body,
      });
    }

    if (typeof location.href !== 'string' || !location.href.startsWith('https://')) {
      throw new RPError({
        printf: ['invalid issuer location %s', location.href],
        body,
      });
    }

    const expectedIssuer = location.href;
    if (registry.has(expectedIssuer)) {
      return registry.get(expectedIssuer);
    }

    const issuer = await this.discover(expectedIssuer);

    if (issuer.issuer !== expectedIssuer) {
      registry.del(issuer.issuer);
      throw new RPError(
        'discovered issuer mismatch, expected %s, got: %s',
        expectedIssuer,
        issuer.issuer,
      );
    }
    return issuer;
  }

  static async discover(uri) {
    const wellKnownUri = resolveWellKnownUri(uri);

    const response = await request.call(this, {
      method: 'GET',
      responseType: 'json',
      url: wellKnownUri,
      headers: {
        Accept: 'application/json',
      },
    });
    const body = processResponse(response);
    return new Issuer({
      ...ISSUER_DEFAULTS,
      ...body,
      [AAD_MULTITENANT]: !!AAD_MULTITENANT_DISCOVERY.find((discoveryURL) =>
        wellKnownUri.startsWith(discoveryURL),
      ),
    });
  }

  async reloadJwksUri() {
    await keystore.call(this, true);
  }

  /* istanbul ignore next */
  [inspect.custom]() {
    return `${this.constructor.name} ${inspect(this.metadata, {
      depth: Infinity,
      colors: process.stdout.isTTY,
      compact: false,
      sorted: true,
    })}`;
  }
}

function resolveWellKnownUri(uri) {
  const parsed = url.parse(uri);
  if (parsed.pathname.includes('/.well-known/')) {
    return uri;
  } else {
    let pathname;
    if (parsed.pathname.endsWith('/')) {
      pathname = `${parsed.pathname}.well-known/openid-configuration`;
    } else {
      pathname = `${parsed.pathname}/.well-known/openid-configuration`;
    }
    return url.format({ ...parsed, pathname });
  }
}

module.exports = Issuer;
