const { inspect } = require('util');
const stdhttp = require('http');
const crypto = require('crypto');
const { strict: assert } = require('assert');
const querystring = require('querystring');
const url = require('url');
const { URL, URLSearchParams } = require('url');

const jose = require('jose');
const tokenHash = require('oidc-token-hash');

const isKeyObject = require('./helpers/is_key_object');
const decodeJWT = require('./helpers/decode_jwt');
const base64url = require('./helpers/base64url');
const defaults = require('./helpers/defaults');
const parseWwwAuthenticate = require('./helpers/www_authenticate_parser');
const { assertSigningAlgValuesSupport, assertIssuerConfiguration } = require('./helpers/assert');
const pick = require('./helpers/pick');
const isPlainObject = require('./helpers/is_plain_object');
const processResponse = require('./helpers/process_response');
const TokenSet = require('./token_set');
const { OPError, RPError } = require('./errors');
const now = require('./helpers/unix_timestamp');
const { random } = require('./helpers/generators');
const request = require('./helpers/request');
const { CLOCK_TOLERANCE } = require('./helpers/consts');
const { keystores } = require('./helpers/weak_cache');
const KeyStore = require('./helpers/keystore');
const clone = require('./helpers/deep_clone');
const { authenticatedPost, resolveResponseType, resolveRedirectUri } = require('./helpers/client');
const { queryKeyStore } = require('./helpers/issuer');
const DeviceFlowHandle = require('./device_flow_handle');

const [major, minor] = process.version
  .slice(1)
  .split('.')
  .map((str) => parseInt(str, 10));

const rsaPssParams = major >= 17 || (major === 16 && minor >= 9);
const retryAttempt = Symbol();
const skipNonceCheck = Symbol();
const skipMaxAgeCheck = Symbol();

function pickCb(input) {
  return pick(
    input,
    'access_token', // OAuth 2.0
    'code', // OAuth 2.0
    'error_description', // OAuth 2.0
    'error_uri', // OAuth 2.0
    'error', // OAuth 2.0
    'expires_in', // OAuth 2.0
    'id_token', // OIDC Core 1.0
    'iss', // draft-ietf-oauth-iss-auth-resp
    'response', // FAPI JARM
    'session_state', // OIDC Session Management
    'state', // OAuth 2.0
    'token_type', // OAuth 2.0
  );
}

function authorizationHeaderValue(token, tokenType = 'Bearer') {
  return `${tokenType} ${token}`;
}

function getSearchParams(input) {
  const parsed = url.parse(input);
  if (!parsed.search) return {};
  return querystring.parse(parsed.search.substring(1));
}

function verifyPresence(payload, jwt, prop) {
  if (payload[prop] === undefined) {
    throw new RPError({
      message: `missing required JWT property ${prop}`,
      jwt,
    });
  }
}

function authorizationParams(params) {
  const authParams = {
    client_id: this.client_id,
    scope: 'openid',
    response_type: resolveResponseType.call(this),
    redirect_uri: resolveRedirectUri.call(this),
    ...params,
  };

  Object.entries(authParams).forEach(([key, value]) => {
    if (value === null || value === undefined) {
      delete authParams[key];
    } else if (key === 'claims' && typeof value === 'object') {
      authParams[key] = JSON.stringify(value);
    } else if (key === 'resource' && Array.isArray(value)) {
      authParams[key] = value;
    } else if (typeof value !== 'string') {
      authParams[key] = String(value);
    }
  });

  return authParams;
}

function getKeystore(jwks) {
  if (
    !isPlainObject(jwks) ||
    !Array.isArray(jwks.keys) ||
    jwks.keys.some((k) => !isPlainObject(k) || !('kty' in k))
  ) {
    throw new TypeError('jwks must be a JSON Web Key Set formatted object');
  }

  return KeyStore.fromJWKS(jwks, { onlyPrivate: true });
}

// if an OP doesnt support client_secret_basic but supports client_secret_post, use it instead
// this is in place to take care of most common pitfalls when first using discovered Issuers without
// the support for default values defined by Discovery 1.0
function checkBasicSupport(client, properties) {
  try {
    const supported = client.issuer.token_endpoint_auth_methods_supported;
    if (!supported.includes(properties.token_endpoint_auth_method)) {
      if (supported.includes('client_secret_post')) {
        properties.token_endpoint_auth_method = 'client_secret_post';
      }
    }
  } catch (err) {}
}

function handleCommonMistakes(client, metadata, properties) {
  if (!metadata.token_endpoint_auth_method) {
    // if no explicit value was provided
    checkBasicSupport(client, properties);
  }

  // :fp: c'mon people... RTFM
  if (metadata.redirect_uri) {
    if (metadata.redirect_uris) {
      throw new TypeError('provide a redirect_uri or redirect_uris, not both');
    }
    properties.redirect_uris = [metadata.redirect_uri];
    delete properties.redirect_uri;
  }

  if (metadata.response_type) {
    if (metadata.response_types) {
      throw new TypeError('provide a response_type or response_types, not both');
    }
    properties.response_types = [metadata.response_type];
    delete properties.response_type;
  }
}

function getDefaultsForEndpoint(endpoint, issuer, properties) {
  if (!issuer[`${endpoint}_endpoint`]) return;

  const tokenEndpointAuthMethod = properties.token_endpoint_auth_method;
  const tokenEndpointAuthSigningAlg = properties.token_endpoint_auth_signing_alg;

  const eam = `${endpoint}_endpoint_auth_method`;
  const easa = `${endpoint}_endpoint_auth_signing_alg`;

  if (properties[eam] === undefined && properties[easa] === undefined) {
    if (tokenEndpointAuthMethod !== undefined) {
      properties[eam] = tokenEndpointAuthMethod;
    }
    if (tokenEndpointAuthSigningAlg !== undefined) {
      properties[easa] = tokenEndpointAuthSigningAlg;
    }
  }
}

class BaseClient {
  #metadata;
  #issuer;
  #aadIssValidation;
  #additionalAuthorizedParties;
  constructor(issuer, aadIssValidation, metadata = {}, jwks, options) {
    this.#metadata = new Map();
    this.#issuer = issuer;
    this.#aadIssValidation = aadIssValidation;

    if (typeof metadata.client_id !== 'string' || !metadata.client_id) {
      throw new TypeError('client_id is required');
    }

    const properties = {
      grant_types: ['authorization_code'],
      id_token_signed_response_alg: 'RS256',
      authorization_signed_response_alg: 'RS256',
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_basic',
      ...(this.fapi()
        ? {
            grant_types: ['authorization_code', 'implicit'],
            id_token_signed_response_alg: 'PS256',
            authorization_signed_response_alg: 'PS256',
            response_types: ['code id_token'],
            tls_client_certificate_bound_access_tokens: true,
            token_endpoint_auth_method: undefined,
          }
        : undefined),
      ...metadata,
    };

    if (this.fapi()) {
      switch (properties.token_endpoint_auth_method) {
        case 'self_signed_tls_client_auth':
        case 'tls_client_auth':
          break;
        case 'private_key_jwt':
          if (!jwks) {
            throw new TypeError('jwks is required');
          }
          break;
        case undefined:
          throw new TypeError('token_endpoint_auth_method is required');
        default:
          throw new TypeError('invalid or unsupported token_endpoint_auth_method');
      }
    }

    handleCommonMistakes(this, metadata, properties);

    assertSigningAlgValuesSupport('token', this.issuer, properties);
    ['introspection', 'revocation'].forEach((endpoint) => {
      getDefaultsForEndpoint(endpoint, this.issuer, properties);
      assertSigningAlgValuesSupport(endpoint, this.issuer, properties);
    });

    Object.entries(properties).forEach(([key, value]) => {
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

    if (jwks !== undefined) {
      const keystore = getKeystore.call(this, jwks);
      keystores.set(this, keystore);
    }

    if (options != null && options.additionalAuthorizedParties) {
      this.#additionalAuthorizedParties = clone(options.additionalAuthorizedParties);
    }

    this[CLOCK_TOLERANCE] = 0;
  }

  authorizationUrl(params = {}) {
    if (!isPlainObject(params)) {
      throw new TypeError('params must be a plain object');
    }
    assertIssuerConfiguration(this.issuer, 'authorization_endpoint');
    const target = new URL(this.issuer.authorization_endpoint);

    for (const [name, value] of Object.entries(authorizationParams.call(this, params))) {
      if (Array.isArray(value)) {
        target.searchParams.delete(name);
        for (const member of value) {
          target.searchParams.append(name, member);
        }
      } else {
        target.searchParams.set(name, value);
      }
    }

    // TODO: is the replace needed?
    return target.href.replace(/\+/g, '%20');
  }

  authorizationPost(params = {}) {
    if (!isPlainObject(params)) {
      throw new TypeError('params must be a plain object');
    }
    const inputs = authorizationParams.call(this, params);
    const formInputs = Object.keys(inputs)
      .map((name) => `<input type="hidden" name="${name}" value="${inputs[name]}"/>`)
      .join('\n');

    return `<!DOCTYPE html>
<head>
<title>Requesting Authorization</title>
</head>
<body onload="javascript:document.forms[0].submit()">
<form method="post" action="${this.issuer.authorization_endpoint}">
  ${formInputs}
</form>
</body>
</html>`;
  }

  endSessionUrl(params = {}) {
    assertIssuerConfiguration(this.issuer, 'end_session_endpoint');

    const { 0: postLogout, length } = this.post_logout_redirect_uris || [];

    const { post_logout_redirect_uri = length === 1 ? postLogout : undefined } = params;

    let id_token_hint;
    ({ id_token_hint, ...params } = params);
    if (id_token_hint instanceof TokenSet) {
      if (!id_token_hint.id_token) {
        throw new TypeError('id_token not present in TokenSet');
      }
      id_token_hint = id_token_hint.id_token;
    }

    const target = url.parse(this.issuer.end_session_endpoint);
    const query = defaults(
      getSearchParams(this.issuer.end_session_endpoint),
      params,
      {
        post_logout_redirect_uri,
        client_id: this.client_id,
      },
      { id_token_hint },
    );

    Object.entries(query).forEach(([key, value]) => {
      if (value === null || value === undefined) {
        delete query[key];
      }
    });

    target.search = null;
    target.query = query;

    return url.format(target);
  }

  callbackParams(input) {
    const isIncomingMessage =
      input instanceof stdhttp.IncomingMessage || (input && input.method && input.url);
    const isString = typeof input === 'string';

    if (!isString && !isIncomingMessage) {
      throw new TypeError(
        '#callbackParams only accepts string urls, http.IncomingMessage or a lookalike',
      );
    }
    if (isIncomingMessage) {
      switch (input.method) {
        case 'GET':
          return pickCb(getSearchParams(input.url));
        case 'POST':
          if (input.body === undefined) {
            throw new TypeError(
              'incoming message body missing, include a body parser prior to this method call',
            );
          }
          switch (typeof input.body) {
            case 'object':
            case 'string':
              if (Buffer.isBuffer(input.body)) {
                return pickCb(querystring.parse(input.body.toString('utf-8')));
              }
              if (typeof input.body === 'string') {
                return pickCb(querystring.parse(input.body));
              }

              return pickCb(input.body);
            default:
              throw new TypeError('invalid IncomingMessage body object');
          }
        default:
          throw new TypeError('invalid IncomingMessage method');
      }
    } else {
      return pickCb(getSearchParams(input));
    }
  }

  async callback(
    redirectUri,
    parameters,
    checks = {},
    { exchangeBody, clientAssertionPayload, DPoP } = {},
  ) {
    let params = pickCb(parameters);

    if (checks.jarm && !('response' in parameters)) {
      throw new RPError({
        message: 'expected a JARM response',
        checks,
        params,
      });
    } else if ('response' in parameters) {
      const decrypted = await this.decryptJARM(params.response);
      params = await this.validateJARM(decrypted);
    }

    if (this.default_max_age && !checks.max_age) {
      checks.max_age = this.default_max_age;
    }

    if (params.state && !checks.state) {
      throw new TypeError('checks.state argument is missing');
    }

    if (!params.state && checks.state) {
      throw new RPError({
        message: 'state missing from the response',
        checks,
        params,
      });
    }

    if (checks.state !== params.state) {
      throw new RPError({
        printf: ['state mismatch, expected %s, got: %s', checks.state, params.state],
        checks,
        params,
      });
    }

    if ('iss' in params) {
      assertIssuerConfiguration(this.issuer, 'issuer');
      if (params.iss !== this.issuer.issuer) {
        throw new RPError({
          printf: ['iss mismatch, expected %s, got: %s', this.issuer.issuer, params.iss],
          params,
        });
      }
    } else if (
      this.issuer.authorization_response_iss_parameter_supported &&
      !('id_token' in params) &&
      !('response' in parameters)
    ) {
      throw new RPError({
        message: 'iss missing from the response',
        params,
      });
    }

    if (params.error) {
      throw new OPError(params);
    }

    const RESPONSE_TYPE_REQUIRED_PARAMS = {
      code: ['code'],
      id_token: ['id_token'],
      token: ['access_token', 'token_type'],
    };

    if (checks.response_type) {
      for (const type of checks.response_type.split(' ')) {
        if (type === 'none') {
          if (params.code || params.id_token || params.access_token) {
            throw new RPError({
              message: 'unexpected params encountered for "none" response',
              checks,
              params,
            });
          }
        } else {
          for (const param of RESPONSE_TYPE_REQUIRED_PARAMS[type]) {
            if (!params[param]) {
              throw new RPError({
                message: `${param} missing from response`,
                checks,
                params,
              });
            }
          }
        }
      }
    }

    if (params.id_token) {
      const tokenset = new TokenSet(params);
      await this.decryptIdToken(tokenset);
      await this.validateIdToken(
        tokenset,
        checks.nonce,
        'authorization',
        checks.max_age,
        checks.state,
      );

      if (!params.code) {
        return tokenset;
      }
    }

    if (params.code) {
      const tokenset = await this.grant(
        {
          ...exchangeBody,
          grant_type: 'authorization_code',
          code: params.code,
          redirect_uri: redirectUri,
          code_verifier: checks.code_verifier,
        },
        { clientAssertionPayload, DPoP },
      );

      await this.decryptIdToken(tokenset);
      await this.validateIdToken(tokenset, checks.nonce, 'token', checks.max_age);

      if (params.session_state) {
        tokenset.session_state = params.session_state;
      }

      return tokenset;
    }

    return new TokenSet(params);
  }

  async oauthCallback(
    redirectUri,
    parameters,
    checks = {},
    { exchangeBody, clientAssertionPayload, DPoP } = {},
  ) {
    let params = pickCb(parameters);

    if (checks.jarm && !('response' in parameters)) {
      throw new RPError({
        message: 'expected a JARM response',
        checks,
        params,
      });
    } else if ('response' in parameters) {
      const decrypted = await this.decryptJARM(params.response);
      params = await this.validateJARM(decrypted);
    }

    if (params.state && !checks.state) {
      throw new TypeError('checks.state argument is missing');
    }

    if (!params.state && checks.state) {
      throw new RPError({
        message: 'state missing from the response',
        checks,
        params,
      });
    }

    if (checks.state !== params.state) {
      throw new RPError({
        printf: ['state mismatch, expected %s, got: %s', checks.state, params.state],
        checks,
        params,
      });
    }

    if ('iss' in params) {
      assertIssuerConfiguration(this.issuer, 'issuer');
      if (params.iss !== this.issuer.issuer) {
        throw new RPError({
          printf: ['iss mismatch, expected %s, got: %s', this.issuer.issuer, params.iss],
          params,
        });
      }
    } else if (
      this.issuer.authorization_response_iss_parameter_supported &&
      !('id_token' in params) &&
      !('response' in parameters)
    ) {
      throw new RPError({
        message: 'iss missing from the response',
        params,
      });
    }

    if (params.error) {
      throw new OPError(params);
    }

    if (typeof params.id_token === 'string' && params.id_token.length) {
      throw new RPError({
        message:
          'id_token detected in the response, you must use client.callback() instead of client.oauthCallback()',
        params,
      });
    }
    delete params.id_token;

    const RESPONSE_TYPE_REQUIRED_PARAMS = {
      code: ['code'],
      token: ['access_token', 'token_type'],
    };

    if (checks.response_type) {
      for (const type of checks.response_type.split(' ')) {
        if (type === 'none') {
          if (params.code || params.id_token || params.access_token) {
            throw new RPError({
              message: 'unexpected params encountered for "none" response',
              checks,
              params,
            });
          }
        }

        if (RESPONSE_TYPE_REQUIRED_PARAMS[type]) {
          for (const param of RESPONSE_TYPE_REQUIRED_PARAMS[type]) {
            if (!params[param]) {
              throw new RPError({
                message: `${param} missing from response`,
                checks,
                params,
              });
            }
          }
        }
      }
    }

    if (params.code) {
      const tokenset = await this.grant(
        {
          ...exchangeBody,
          grant_type: 'authorization_code',
          code: params.code,
          redirect_uri: redirectUri,
          code_verifier: checks.code_verifier,
        },
        { clientAssertionPayload, DPoP },
      );

      if (typeof tokenset.id_token === 'string' && tokenset.id_token.length) {
        throw new RPError({
          message:
            'id_token detected in the response, you must use client.callback() instead of client.oauthCallback()',
          params,
        });
      }
      delete tokenset.id_token;

      return tokenset;
    }

    return new TokenSet(params);
  }

  async decryptIdToken(token) {
    if (!this.id_token_encrypted_response_alg) {
      return token;
    }

    let idToken = token;

    if (idToken instanceof TokenSet) {
      if (!idToken.id_token) {
        throw new TypeError('id_token not present in TokenSet');
      }
      idToken = idToken.id_token;
    }

    const expectedAlg = this.id_token_encrypted_response_alg;
    const expectedEnc = this.id_token_encrypted_response_enc;

    const result = await this.decryptJWE(idToken, expectedAlg, expectedEnc);

    if (token instanceof TokenSet) {
      token.id_token = result;
      return token;
    }

    return result;
  }

  async validateJWTUserinfo(body) {
    const expectedAlg = this.userinfo_signed_response_alg;

    return this.validateJWT(body, expectedAlg, []);
  }

  async decryptJARM(response) {
    if (!this.authorization_encrypted_response_alg) {
      return response;
    }

    const expectedAlg = this.authorization_encrypted_response_alg;
    const expectedEnc = this.authorization_encrypted_response_enc;

    return this.decryptJWE(response, expectedAlg, expectedEnc);
  }

  async decryptJWTUserinfo(body) {
    if (!this.userinfo_encrypted_response_alg) {
      return body;
    }

    const expectedAlg = this.userinfo_encrypted_response_alg;
    const expectedEnc = this.userinfo_encrypted_response_enc;

    return this.decryptJWE(body, expectedAlg, expectedEnc);
  }

  async decryptJWE(jwe, expectedAlg, expectedEnc = 'A128CBC-HS256') {
    const header = JSON.parse(base64url.decode(jwe.split('.')[0]));

    if (header.alg !== expectedAlg) {
      throw new RPError({
        printf: ['unexpected JWE alg received, expected %s, got: %s', expectedAlg, header.alg],
        jwt: jwe,
      });
    }

    if (header.enc !== expectedEnc) {
      throw new RPError({
        printf: ['unexpected JWE enc received, expected %s, got: %s', expectedEnc, header.enc],
        jwt: jwe,
      });
    }

    const getPlaintext = (result) => new TextDecoder().decode(result.plaintext);
    let plaintext;
    if (expectedAlg.match(/^(?:RSA|ECDH)/)) {
      const keystore = await keystores.get(this);

      const protectedHeader = jose.decodeProtectedHeader(jwe);

      for (const key of keystore.all({
        ...protectedHeader,
        use: 'enc',
      })) {
        plaintext = await jose
          .compactDecrypt(jwe, await key.keyObject(protectedHeader.alg))
          .then(getPlaintext, () => {});
        if (plaintext) break;
      }
    } else {
      plaintext = await jose
        .compactDecrypt(jwe, this.secretForAlg(expectedAlg === 'dir' ? expectedEnc : expectedAlg))
        .then(getPlaintext, () => {});
    }

    if (!plaintext) {
      throw new RPError({
        message: 'failed to decrypt JWE',
        jwt: jwe,
      });
    }
    return plaintext;
  }

  async validateIdToken(tokenSet, nonce, returnedBy, maxAge, state) {
    let idToken = tokenSet;

    const expectedAlg = this.id_token_signed_response_alg;

    const isTokenSet = idToken instanceof TokenSet;

    if (isTokenSet) {
      if (!idToken.id_token) {
        throw new TypeError('id_token not present in TokenSet');
      }
      idToken = idToken.id_token;
    }

    idToken = String(idToken);

    const timestamp = now();
    const { protected: header, payload, key } = await this.validateJWT(idToken, expectedAlg);

    if (typeof maxAge === 'number' || (maxAge !== skipMaxAgeCheck && this.require_auth_time)) {
      if (!payload.auth_time) {
        throw new RPError({
          message: 'missing required JWT property auth_time',
          jwt: idToken,
        });
      }
      if (typeof payload.auth_time !== 'number') {
        throw new RPError({
          message: 'JWT auth_time claim must be a JSON numeric value',
          jwt: idToken,
        });
      }
    }

    if (
      typeof maxAge === 'number' &&
      payload.auth_time + maxAge < timestamp - this[CLOCK_TOLERANCE]
    ) {
      throw new RPError({
        printf: [
          'too much time has elapsed since the last End-User authentication, max_age %i, auth_time: %i, now %i',
          maxAge,
          payload.auth_time,
          timestamp - this[CLOCK_TOLERANCE],
        ],
        now: timestamp,
        tolerance: this[CLOCK_TOLERANCE],
        auth_time: payload.auth_time,
        jwt: idToken,
      });
    }

    if (
      nonce !== skipNonceCheck &&
      (payload.nonce || nonce !== undefined) &&
      payload.nonce !== nonce
    ) {
      throw new RPError({
        printf: ['nonce mismatch, expected %s, got: %s', nonce, payload.nonce],
        jwt: idToken,
      });
    }

    if (returnedBy === 'authorization') {
      if (!payload.at_hash && tokenSet.access_token) {
        throw new RPError({
          message: 'missing required property at_hash',
          jwt: idToken,
        });
      }

      if (!payload.c_hash && tokenSet.code) {
        throw new RPError({
          message: 'missing required property c_hash',
          jwt: idToken,
        });
      }

      if (this.fapi()) {
        if (!payload.s_hash && (tokenSet.state || state)) {
          throw new RPError({
            message: 'missing required property s_hash',
            jwt: idToken,
          });
        }
      }

      if (payload.s_hash) {
        if (!state) {
          throw new TypeError('cannot verify s_hash, "checks.state" property not provided');
        }

        try {
          tokenHash.validate(
            { claim: 's_hash', source: 'state' },
            payload.s_hash,
            state,
            header.alg,
            key.jwk && key.jwk.crv,
          );
        } catch (err) {
          throw new RPError({ message: err.message, jwt: idToken });
        }
      }
    }

    if (this.fapi() && payload.iat < timestamp - 3600) {
      throw new RPError({
        printf: ['JWT issued too far in the past, now %i, iat %i', timestamp, payload.iat],
        now: timestamp,
        tolerance: this[CLOCK_TOLERANCE],
        iat: payload.iat,
        jwt: idToken,
      });
    }

    if (tokenSet.access_token && payload.at_hash !== undefined) {
      try {
        tokenHash.validate(
          { claim: 'at_hash', source: 'access_token' },
          payload.at_hash,
          tokenSet.access_token,
          header.alg,
          key.jwk && key.jwk.crv,
        );
      } catch (err) {
        throw new RPError({ message: err.message, jwt: idToken });
      }
    }

    if (tokenSet.code && payload.c_hash !== undefined) {
      try {
        tokenHash.validate(
          { claim: 'c_hash', source: 'code' },
          payload.c_hash,
          tokenSet.code,
          header.alg,
          key.jwk && key.jwk.crv,
        );
      } catch (err) {
        throw new RPError({ message: err.message, jwt: idToken });
      }
    }

    return tokenSet;
  }

  async validateJWT(jwt, expectedAlg, required = ['iss', 'sub', 'aud', 'exp', 'iat']) {
    const isSelfIssued = this.issuer.issuer === 'https://self-issued.me';
    const timestamp = now();
    let header;
    let payload;
    try {
      ({ header, payload } = decodeJWT(jwt, { complete: true }));
    } catch (err) {
      throw new RPError({
        printf: ['failed to decode JWT (%s: %s)', err.name, err.message],
        jwt,
      });
    }

    if (header.alg !== expectedAlg) {
      throw new RPError({
        printf: ['unexpected JWT alg received, expected %s, got: %s', expectedAlg, header.alg],
        jwt,
      });
    }

    if (isSelfIssued) {
      required = [...required, 'sub_jwk'];
    }

    required.forEach(verifyPresence.bind(undefined, payload, jwt));

    if (payload.iss !== undefined) {
      let expectedIss = this.issuer.issuer;

      if (this.#aadIssValidation) {
        expectedIss = this.issuer.issuer.replace('{tenantid}', payload.tid);
      }

      if (payload.iss !== expectedIss) {
        throw new RPError({
          printf: ['unexpected iss value, expected %s, got: %s', expectedIss, payload.iss],
          jwt,
        });
      }
    }

    if (payload.iat !== undefined) {
      if (typeof payload.iat !== 'number') {
        throw new RPError({
          message: 'JWT iat claim must be a JSON numeric value',
          jwt,
        });
      }
    }

    if (payload.nbf !== undefined) {
      if (typeof payload.nbf !== 'number') {
        throw new RPError({
          message: 'JWT nbf claim must be a JSON numeric value',
          jwt,
        });
      }
      if (payload.nbf > timestamp + this[CLOCK_TOLERANCE]) {
        throw new RPError({
          printf: [
            'JWT not active yet, now %i, nbf %i',
            timestamp + this[CLOCK_TOLERANCE],
            payload.nbf,
          ],
          now: timestamp,
          tolerance: this[CLOCK_TOLERANCE],
          nbf: payload.nbf,
          jwt,
        });
      }
    }

    if (payload.exp !== undefined) {
      if (typeof payload.exp !== 'number') {
        throw new RPError({
          message: 'JWT exp claim must be a JSON numeric value',
          jwt,
        });
      }
      if (timestamp - this[CLOCK_TOLERANCE] >= payload.exp) {
        throw new RPError({
          printf: ['JWT expired, now %i, exp %i', timestamp - this[CLOCK_TOLERANCE], payload.exp],
          now: timestamp,
          tolerance: this[CLOCK_TOLERANCE],
          exp: payload.exp,
          jwt,
        });
      }
    }

    if (payload.aud !== undefined) {
      if (Array.isArray(payload.aud)) {
        if (payload.aud.length > 1 && !payload.azp) {
          throw new RPError({
            message: 'missing required JWT property azp',
            jwt,
          });
        }

        if (!payload.aud.includes(this.client_id)) {
          throw new RPError({
            printf: [
              'aud is missing the client_id, expected %s to be included in %j',
              this.client_id,
              payload.aud,
            ],
            jwt,
          });
        }
      } else if (payload.aud !== this.client_id) {
        throw new RPError({
          printf: ['aud mismatch, expected %s, got: %s', this.client_id, payload.aud],
          jwt,
        });
      }
    }

    if (payload.azp !== undefined) {
      let additionalAuthorizedParties = this.#additionalAuthorizedParties;

      if (typeof additionalAuthorizedParties === 'string') {
        additionalAuthorizedParties = [this.client_id, additionalAuthorizedParties];
      } else if (Array.isArray(additionalAuthorizedParties)) {
        additionalAuthorizedParties = [this.client_id, ...additionalAuthorizedParties];
      } else {
        additionalAuthorizedParties = [this.client_id];
      }

      if (!additionalAuthorizedParties.includes(payload.azp)) {
        throw new RPError({
          printf: ['azp mismatch, got: %s', payload.azp],
          jwt,
        });
      }
    }

    let keys;

    if (isSelfIssued) {
      try {
        assert(isPlainObject(payload.sub_jwk));
        const key = await jose.importJWK(payload.sub_jwk, header.alg);
        assert.equal(key.type, 'public');
        keys = [
          {
            keyObject() {
              return key;
            },
          },
        ];
      } catch (err) {
        throw new RPError({
          message: 'failed to use sub_jwk claim as an asymmetric JSON Web Key',
          jwt,
        });
      }
      if ((await jose.calculateJwkThumbprint(payload.sub_jwk)) !== payload.sub) {
        throw new RPError({
          message: 'failed to match the subject with sub_jwk',
          jwt,
        });
      }
    } else if (header.alg.startsWith('HS')) {
      keys = [this.secretForAlg(header.alg)];
    } else if (header.alg !== 'none') {
      keys = await queryKeyStore.call(this.issuer, { ...header, use: 'sig' });
    }

    if (!keys && header.alg === 'none') {
      return { protected: header, payload };
    }

    for (const key of keys) {
      const verified = await jose
        .compactVerify(jwt, key instanceof Uint8Array ? key : await key.keyObject(header.alg))
        .catch(() => {});
      if (verified) {
        return {
          payload,
          protected: verified.protectedHeader,
          key,
        };
      }
    }

    throw new RPError({
      message: 'failed to validate JWT signature',
      jwt,
    });
  }

  async refresh(refreshToken, { exchangeBody, clientAssertionPayload, DPoP } = {}) {
    let token = refreshToken;

    if (token instanceof TokenSet) {
      if (!token.refresh_token) {
        throw new TypeError('refresh_token not present in TokenSet');
      }
      token = token.refresh_token;
    }

    const tokenset = await this.grant(
      {
        ...exchangeBody,
        grant_type: 'refresh_token',
        refresh_token: String(token),
      },
      { clientAssertionPayload, DPoP },
    );

    if (tokenset.id_token) {
      await this.decryptIdToken(tokenset);
      await this.validateIdToken(tokenset, skipNonceCheck, 'token', skipMaxAgeCheck);

      if (refreshToken instanceof TokenSet && refreshToken.id_token) {
        const expectedSub = refreshToken.claims().sub;
        const actualSub = tokenset.claims().sub;
        if (actualSub !== expectedSub) {
          throw new RPError({
            printf: ['sub mismatch, expected %s, got: %s', expectedSub, actualSub],
            jwt: tokenset.id_token,
          });
        }
      }
    }

    return tokenset;
  }

  async requestResource(
    resourceUrl,
    accessToken,
    {
      method,
      headers,
      body,
      DPoP,
      tokenType = DPoP
        ? 'DPoP'
        : accessToken instanceof TokenSet
        ? accessToken.token_type
        : 'Bearer',
    } = {},
    retry,
  ) {
    if (accessToken instanceof TokenSet) {
      if (!accessToken.access_token) {
        throw new TypeError('access_token not present in TokenSet');
      }
      accessToken = accessToken.access_token;
    }

    if (!accessToken) {
      throw new TypeError('no access token provided');
    } else if (typeof accessToken !== 'string') {
      throw new TypeError('invalid access token provided');
    }

    const requestOpts = {
      headers: {
        Authorization: authorizationHeaderValue(accessToken, tokenType),
        ...headers,
      },
      body,
    };

    const mTLS = !!this.tls_client_certificate_bound_access_tokens;

    const response = await request.call(
      this,
      {
        ...requestOpts,
        responseType: 'buffer',
        method,
        url: resourceUrl,
      },
      { accessToken, mTLS, DPoP },
    );

    const wwwAuthenticate = response.headers['www-authenticate'];
    if (
      retry !== retryAttempt &&
      wwwAuthenticate &&
      wwwAuthenticate.toLowerCase().startsWith('dpop ') &&
      parseWwwAuthenticate(wwwAuthenticate).error === 'use_dpop_nonce'
    ) {
      return this.requestResource(resourceUrl, accessToken, {
        method,
        headers,
        body,
        DPoP,
        tokenType,
      });
    }

    return response;
  }

  async userinfo(accessToken, { method = 'GET', via = 'header', tokenType, params, DPoP } = {}) {
    assertIssuerConfiguration(this.issuer, 'userinfo_endpoint');
    const options = {
      tokenType,
      method: String(method).toUpperCase(),
      DPoP,
    };

    if (options.method !== 'GET' && options.method !== 'POST') {
      throw new TypeError('#userinfo() method can only be POST or a GET');
    }

    if (via === 'body' && options.method !== 'POST') {
      throw new TypeError('can only send body on POST');
    }

    const jwt = !!(this.userinfo_signed_response_alg || this.userinfo_encrypted_response_alg);

    if (jwt) {
      options.headers = { Accept: 'application/jwt' };
    } else {
      options.headers = { Accept: 'application/json' };
    }
    const mTLS = !!this.tls_client_certificate_bound_access_tokens;

    let targetUrl;
    if (mTLS && this.issuer.mtls_endpoint_aliases) {
      targetUrl = this.issuer.mtls_endpoint_aliases.userinfo_endpoint;
    }

    targetUrl = new URL(targetUrl || this.issuer.userinfo_endpoint);

    if (via === 'body') {
      options.headers.Authorization = undefined;
      options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
      options.body = new URLSearchParams();
      options.body.append(
        'access_token',
        accessToken instanceof TokenSet ? accessToken.access_token : accessToken,
      );
    }

    // handle additional parameters, GET via querystring, POST via urlencoded body
    if (params) {
      if (options.method === 'GET') {
        Object.entries(params).forEach(([key, value]) => {
          targetUrl.searchParams.append(key, value);
        });
      } else if (options.body) {
        // POST && via body
        Object.entries(params).forEach(([key, value]) => {
          options.body.append(key, value);
        });
      } else {
        // POST && via header
        options.body = new URLSearchParams();
        options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
        Object.entries(params).forEach(([key, value]) => {
          options.body.append(key, value);
        });
      }
    }

    if (options.body) {
      options.body = options.body.toString();
    }

    const response = await this.requestResource(targetUrl, accessToken, options);

    let parsed = processResponse(response, { bearer: true });

    if (jwt) {
      if (!/^application\/jwt/.test(response.headers['content-type'])) {
        throw new RPError({
          message: 'expected application/jwt response from the userinfo_endpoint',
          response,
        });
      }

      const body = response.body.toString();
      const userinfo = await this.decryptJWTUserinfo(body);
      if (!this.userinfo_signed_response_alg) {
        try {
          parsed = JSON.parse(userinfo);
          assert(isPlainObject(parsed));
        } catch (err) {
          throw new RPError({
            message: 'failed to parse userinfo JWE payload as JSON',
            jwt: userinfo,
          });
        }
      } else {
        ({ payload: parsed } = await this.validateJWTUserinfo(userinfo));
      }
    } else {
      try {
        parsed = JSON.parse(response.body);
      } catch (err) {
        Object.defineProperty(err, 'response', { value: response });
        throw err;
      }
    }

    if (accessToken instanceof TokenSet && accessToken.id_token) {
      const expectedSub = accessToken.claims().sub;
      if (parsed.sub !== expectedSub) {
        throw new RPError({
          printf: ['userinfo sub mismatch, expected %s, got: %s', expectedSub, parsed.sub],
          body: parsed,
          jwt: accessToken.id_token,
        });
      }
    }

    return parsed;
  }

  encryptionSecret(len) {
    const hash = len <= 256 ? 'sha256' : len <= 384 ? 'sha384' : len <= 512 ? 'sha512' : false;
    if (!hash) {
      throw new Error('unsupported symmetric encryption key derivation');
    }

    return crypto
      .createHash(hash)
      .update(this.client_secret)
      .digest()
      .slice(0, len / 8);
  }

  secretForAlg(alg) {
    if (!this.client_secret) {
      throw new TypeError('client_secret is required');
    }

    if (/^A(\d{3})(?:GCM)?KW$/.test(alg)) {
      return this.encryptionSecret(parseInt(RegExp.$1, 10));
    }

    if (/^A(\d{3})(?:GCM|CBC-HS(\d{3}))$/.test(alg)) {
      return this.encryptionSecret(parseInt(RegExp.$2 || RegExp.$1, 10));
    }

    return new TextEncoder().encode(this.client_secret);
  }

  async grant(body, { clientAssertionPayload, DPoP } = {}, retry) {
    assertIssuerConfiguration(this.issuer, 'token_endpoint');
    const response = await authenticatedPost.call(
      this,
      'token',
      {
        form: body,
        responseType: 'json',
      },
      { clientAssertionPayload, DPoP },
    );
    let responseBody;
    try {
      responseBody = processResponse(response);
    } catch (err) {
      if (retry !== retryAttempt && err instanceof OPError && err.error === 'use_dpop_nonce') {
        return this.grant(body, { clientAssertionPayload, DPoP }, retryAttempt);
      }
      throw err;
    }

    return new TokenSet(responseBody);
  }

  async deviceAuthorization(params = {}, { exchangeBody, clientAssertionPayload, DPoP } = {}) {
    assertIssuerConfiguration(this.issuer, 'device_authorization_endpoint');
    assertIssuerConfiguration(this.issuer, 'token_endpoint');

    const body = authorizationParams.call(this, {
      client_id: this.client_id,
      redirect_uri: null,
      response_type: null,
      ...params,
    });

    const response = await authenticatedPost.call(
      this,
      'device_authorization',
      {
        responseType: 'json',
        form: body,
      },
      { clientAssertionPayload, endpointAuthMethod: 'token' },
    );
    const responseBody = processResponse(response);

    return new DeviceFlowHandle({
      client: this,
      exchangeBody,
      clientAssertionPayload,
      response: responseBody,
      maxAge: params.max_age,
      DPoP,
    });
  }

  async revoke(token, hint, { revokeBody, clientAssertionPayload } = {}) {
    assertIssuerConfiguration(this.issuer, 'revocation_endpoint');
    if (hint !== undefined && typeof hint !== 'string') {
      throw new TypeError('hint must be a string');
    }

    const form = { ...revokeBody, token };

    if (hint) {
      form.token_type_hint = hint;
    }

    const response = await authenticatedPost.call(
      this,
      'revocation',
      {
        form,
      },
      { clientAssertionPayload },
    );
    processResponse(response, { body: false });
  }

  async introspect(token, hint, { introspectBody, clientAssertionPayload } = {}) {
    assertIssuerConfiguration(this.issuer, 'introspection_endpoint');
    if (hint !== undefined && typeof hint !== 'string') {
      throw new TypeError('hint must be a string');
    }

    const form = { ...introspectBody, token };
    if (hint) {
      form.token_type_hint = hint;
    }

    const response = await authenticatedPost.call(
      this,
      'introspection',
      { form, responseType: 'json' },
      { clientAssertionPayload },
    );

    const responseBody = processResponse(response);

    return responseBody;
  }

  static async register(metadata, options = {}) {
    const { initialAccessToken, jwks, ...clientOptions } = options;

    assertIssuerConfiguration(this.issuer, 'registration_endpoint');

    if (jwks !== undefined && !(metadata.jwks || metadata.jwks_uri)) {
      const keystore = await getKeystore.call(this, jwks);
      metadata.jwks = keystore.toJWKS();
    }

    const response = await request.call(this, {
      headers: {
        Accept: 'application/json',
        ...(initialAccessToken
          ? {
              Authorization: authorizationHeaderValue(initialAccessToken),
            }
          : undefined),
      },
      responseType: 'json',
      json: metadata,
      url: this.issuer.registration_endpoint,
      method: 'POST',
    });
    const responseBody = processResponse(response, { statusCode: 201, bearer: true });

    return new this(responseBody, jwks, clientOptions);
  }

  get metadata() {
    return clone(Object.fromEntries(this.#metadata.entries()));
  }

  static async fromUri(registrationClientUri, registrationAccessToken, jwks, clientOptions) {
    const response = await request.call(this, {
      method: 'GET',
      url: registrationClientUri,
      responseType: 'json',
      headers: {
        Authorization: authorizationHeaderValue(registrationAccessToken),
        Accept: 'application/json',
      },
    });
    const responseBody = processResponse(response, { bearer: true });

    return new this(responseBody, jwks, clientOptions);
  }

  async requestObject(
    requestObject = {},
    {
      sign: signingAlgorithm = this.request_object_signing_alg || 'none',
      encrypt: {
        alg: eKeyManagement = this.request_object_encryption_alg,
        enc: eContentEncryption = this.request_object_encryption_enc || 'A128CBC-HS256',
      } = {},
    } = {},
  ) {
    if (!isPlainObject(requestObject)) {
      throw new TypeError('requestObject must be a plain object');
    }

    let signed;
    let key;
    const unix = now();
    const header = { alg: signingAlgorithm, typ: 'oauth-authz-req+jwt' };
    const payload = JSON.stringify(
      defaults({}, requestObject, {
        iss: this.client_id,
        aud: this.issuer.issuer,
        client_id: this.client_id,
        jti: random(),
        iat: unix,
        exp: unix + 300,
        ...(this.fapi() ? { nbf: unix } : undefined),
      }),
    );
    if (signingAlgorithm === 'none') {
      signed = [base64url.encode(JSON.stringify(header)), base64url.encode(payload), ''].join('.');
    } else {
      const symmetric = signingAlgorithm.startsWith('HS');
      if (symmetric) {
        key = this.secretForAlg(signingAlgorithm);
      } else {
        const keystore = await keystores.get(this);

        if (!keystore) {
          throw new TypeError(
            `no keystore present for client, cannot sign using alg ${signingAlgorithm}`,
          );
        }
        key = keystore.get({ alg: signingAlgorithm, use: 'sig' });
        if (!key) {
          throw new TypeError(`no key to sign with found for alg ${signingAlgorithm}`);
        }
      }

      signed = await new jose.CompactSign(new TextEncoder().encode(payload))
        .setProtectedHeader({
          ...header,
          kid: symmetric ? undefined : key.jwk.kid,
        })
        .sign(symmetric ? key : await key.keyObject(signingAlgorithm));
    }

    if (!eKeyManagement) {
      return signed;
    }

    const fields = { alg: eKeyManagement, enc: eContentEncryption, cty: 'oauth-authz-req+jwt' };

    if (fields.alg.match(/^(RSA|ECDH)/)) {
      [key] = await queryKeyStore.call(
        this.issuer,
        { alg: fields.alg, use: 'enc' },
        { allowMulti: true },
      );
    } else {
      key = this.secretForAlg(fields.alg === 'dir' ? fields.enc : fields.alg);
    }

    return new jose.CompactEncrypt(new TextEncoder().encode(signed))
      .setProtectedHeader({
        ...fields,
        kid: key instanceof Uint8Array ? undefined : key.jwk.kid,
      })
      .encrypt(key instanceof Uint8Array ? key : await key.keyObject(fields.alg));
  }

  async pushedAuthorizationRequest(params = {}, { clientAssertionPayload } = {}) {
    assertIssuerConfiguration(this.issuer, 'pushed_authorization_request_endpoint');

    const body = {
      ...('request' in params ? params : authorizationParams.call(this, params)),
      client_id: this.client_id,
    };

    const response = await authenticatedPost.call(
      this,
      'pushed_authorization_request',
      {
        responseType: 'json',
        form: body,
      },
      { clientAssertionPayload, endpointAuthMethod: 'token' },
    );
    const responseBody = processResponse(response, { statusCode: 201 });

    if (!('expires_in' in responseBody)) {
      throw new RPError({
        message: 'expected expires_in in Pushed Authorization Successful Response',
        response,
      });
    }
    if (typeof responseBody.expires_in !== 'number') {
      throw new RPError({
        message: 'invalid expires_in value in Pushed Authorization Successful Response',
        response,
      });
    }
    if (!('request_uri' in responseBody)) {
      throw new RPError({
        message: 'expected request_uri in Pushed Authorization Successful Response',
        response,
      });
    }
    if (typeof responseBody.request_uri !== 'string') {
      throw new RPError({
        message: 'invalid request_uri value in Pushed Authorization Successful Response',
        response,
      });
    }

    return responseBody;
  }

  get issuer() {
    return this.#issuer;
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

  fapi() {
    return this.constructor.name === 'FAPI1Client';
  }

  async validateJARM(response) {
    const expectedAlg = this.authorization_signed_response_alg;
    const { payload } = await this.validateJWT(response, expectedAlg, ['iss', 'exp', 'aud']);
    return pickCb(payload);
  }

  /**
   * @name dpopProof
   * @api private
   */
  async dpopProof(payload, privateKeyInput, accessToken) {
    if (!isPlainObject(payload)) {
      throw new TypeError('payload must be a plain object');
    }

    let privateKey;
    if (isKeyObject(privateKeyInput)) {
      privateKey = privateKeyInput;
    } else if (privateKeyInput[Symbol.toStringTag] === 'CryptoKey') {
      privateKey = privateKeyInput;
    } else if (jose.cryptoRuntime === 'node:crypto') {
      privateKey = crypto.createPrivateKey(privateKeyInput);
    } else {
      throw new TypeError('unrecognized crypto runtime');
    }

    if (privateKey.type !== 'private') {
      throw new TypeError('"DPoP" option must be a private key');
    }
    let alg = determineDPoPAlgorithm.call(this, privateKey, privateKeyInput);

    if (!alg) {
      throw new TypeError('could not determine DPoP JWS Algorithm');
    }

    return new jose.SignJWT({
      ath: accessToken
        ? base64url.encode(crypto.createHash('sha256').update(accessToken).digest())
        : undefined,
      ...payload,
    })
      .setProtectedHeader({
        alg,
        typ: 'dpop+jwt',
        jwk: await getJwk(privateKey, privateKeyInput),
      })
      .setIssuedAt()
      .setJti(random())
      .sign(privateKey);
  }
}

function determineDPoPAlgorithmFromCryptoKey(cryptoKey) {
  switch (cryptoKey.algorithm.name) {
    case 'Ed25519':
    case 'Ed448':
      return 'EdDSA';
    case 'ECDSA': {
      switch (cryptoKey.algorithm.namedCurve) {
        case 'P-256':
          return 'ES256';
        case 'P-384':
          return 'ES384';
        case 'P-521':
          return 'ES512';
        default:
          break;
      }
      break;
    }
    case 'RSASSA-PKCS1-v1_5':
      return `RS${cryptoKey.algorithm.hash.name.slice(4)}`;
    case 'RSA-PSS':
      return `PS${cryptoKey.algorithm.hash.name.slice(4)}`;
    default:
      throw new TypeError('unsupported DPoP private key');
  }
}

let determineDPoPAlgorithm;
if (jose.cryptoRuntime === 'node:crypto') {
  determineDPoPAlgorithm = function (privateKey, privateKeyInput) {
    if (privateKeyInput[Symbol.toStringTag] === 'CryptoKey') {
      return determineDPoPAlgorithmFromCryptoKey(privateKey);
    }

    switch (privateKey.asymmetricKeyType) {
      case 'ed25519':
      case 'ed448':
        return 'EdDSA';
      case 'ec':
        return determineEcAlgorithm(privateKey, privateKeyInput);
      case 'rsa':
      case rsaPssParams && 'rsa-pss':
        return determineRsaAlgorithm(
          privateKey,
          privateKeyInput,
          this.issuer.dpop_signing_alg_values_supported,
        );
      default:
        throw new TypeError('unsupported DPoP private key');
    }
  };

  const RSPS = /^(?:RS|PS)(?:256|384|512)$/;
  function determineRsaAlgorithm(privateKey, privateKeyInput, valuesSupported) {
    if (
      typeof privateKeyInput === 'object' &&
      privateKeyInput.format === 'jwk' &&
      privateKeyInput.key &&
      privateKeyInput.key.alg
    ) {
      return privateKeyInput.key.alg;
    }

    if (Array.isArray(valuesSupported)) {
      let candidates = valuesSupported.filter(RegExp.prototype.test.bind(RSPS));
      if (privateKey.asymmetricKeyType === 'rsa-pss') {
        candidates = candidates.filter((value) => value.startsWith('PS'));
      }
      return ['PS256', 'PS384', 'PS512', 'RS256', 'RS384', 'RS384'].find((preferred) =>
        candidates.includes(preferred),
      );
    }

    return 'PS256';
  }

  const p256 = Buffer.from([42, 134, 72, 206, 61, 3, 1, 7]);
  const p384 = Buffer.from([43, 129, 4, 0, 34]);
  const p521 = Buffer.from([43, 129, 4, 0, 35]);
  const secp256k1 = Buffer.from([43, 129, 4, 0, 10]);

  function determineEcAlgorithm(privateKey, privateKeyInput) {
    // If input was a JWK
    switch (
      typeof privateKeyInput === 'object' &&
      typeof privateKeyInput.key === 'object' &&
      privateKeyInput.key.crv
    ) {
      case 'P-256':
        return 'ES256';
      case 'secp256k1':
        return 'ES256K';
      case 'P-384':
        return 'ES384';
      case 'P-512':
        return 'ES512';
      default:
        break;
    }

    const buf = privateKey.export({ format: 'der', type: 'pkcs8' });
    const i = buf[1] < 128 ? 17 : 18;
    const len = buf[i];
    const curveOid = buf.slice(i + 1, i + 1 + len);
    if (curveOid.equals(p256)) {
      return 'ES256';
    }

    if (curveOid.equals(p384)) {
      return 'ES384';
    }
    if (curveOid.equals(p521)) {
      return 'ES512';
    }

    if (curveOid.equals(secp256k1)) {
      return 'ES256K';
    }

    throw new TypeError('unsupported DPoP private key curve');
  }
} else {
  determineDPoPAlgorithm = determineDPoPAlgorithmFromCryptoKey;
}

const jwkCache = new WeakMap();
async function getJwk(keyObject, privateKeyInput) {
  if (
    jose.cryptoRuntime === 'node:crypto' &&
    typeof privateKeyInput === 'object' &&
    typeof privateKeyInput.key === 'object' &&
    privateKeyInput.format === 'jwk'
  ) {
    return pick(privateKeyInput.key, 'kty', 'crv', 'x', 'y', 'e', 'n');
  }

  if (jwkCache.has(privateKeyInput)) {
    return jwkCache.get(privateKeyInput);
  }

  const jwk = pick(await jose.exportJWK(keyObject), 'kty', 'crv', 'x', 'y', 'e', 'n');

  if (isKeyObject(privateKeyInput) || jose.cryptoRuntime === 'WebCryptoAPI') {
    jwkCache.set(privateKeyInput, jwk);
  }

  return jwk;
}

module.exports = (issuer, aadIssValidation = false) =>
  class Client extends BaseClient {
    constructor(...args) {
      super(issuer, aadIssValidation, ...args);
    }

    static get issuer() {
      return issuer;
    }
  };

module.exports.BaseClient = BaseClient;
