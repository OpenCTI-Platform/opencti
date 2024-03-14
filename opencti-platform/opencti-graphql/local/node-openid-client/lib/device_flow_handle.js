const { inspect } = require('util');

const { RPError, OPError } = require('./errors');
const now = require('./helpers/unix_timestamp');

class DeviceFlowHandle {
  #aborted;
  #client;
  #clientAssertionPayload;
  #DPoP;
  #exchangeBody;
  #expires_at;
  #interval;
  #maxAge;
  #response;
  constructor({ client, exchangeBody, clientAssertionPayload, response, maxAge, DPoP }) {
    ['verification_uri', 'user_code', 'device_code'].forEach((prop) => {
      if (typeof response[prop] !== 'string' || !response[prop]) {
        throw new RPError(
          `expected ${prop} string to be returned by Device Authorization Response, got %j`,
          response[prop],
        );
      }
    });

    if (!Number.isSafeInteger(response.expires_in)) {
      throw new RPError(
        'expected expires_in number to be returned by Device Authorization Response, got %j',
        response.expires_in,
      );
    }

    this.#expires_at = now() + response.expires_in;
    this.#client = client;
    this.#DPoP = DPoP;
    this.#maxAge = maxAge;
    this.#exchangeBody = exchangeBody;
    this.#clientAssertionPayload = clientAssertionPayload;
    this.#response = response;
    this.#interval = response.interval * 1000 || 5000;
  }

  abort() {
    this.#aborted = true;
  }

  async poll({ signal } = {}) {
    if ((signal && signal.aborted) || this.#aborted) {
      throw new RPError('polling aborted');
    }

    if (this.expired()) {
      throw new RPError(
        'the device code %j has expired and the device authorization session has concluded',
        this.device_code,
      );
    }

    await new Promise((resolve) => setTimeout(resolve, this.#interval));

    let tokenset;
    try {
      tokenset = await this.#client.grant(
        {
          ...this.#exchangeBody,
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: this.device_code,
        },
        { clientAssertionPayload: this.#clientAssertionPayload, DPoP: this.#DPoP },
      );
    } catch (err) {
      switch (err instanceof OPError && err.error) {
        case 'slow_down':
          this.#interval += 5000;
        case 'authorization_pending':
          return this.poll({ signal });
        default:
          throw err;
      }
    }

    if ('id_token' in tokenset) {
      await this.#client.decryptIdToken(tokenset);
      await this.#client.validateIdToken(tokenset, undefined, 'token', this.#maxAge);
    }

    return tokenset;
  }

  get device_code() {
    return this.#response.device_code;
  }

  get user_code() {
    return this.#response.user_code;
  }

  get verification_uri() {
    return this.#response.verification_uri;
  }

  get verification_uri_complete() {
    return this.#response.verification_uri_complete;
  }

  get expires_in() {
    return Math.max.apply(null, [this.#expires_at - now(), 0]);
  }

  expired() {
    return this.expires_in === 0;
  }

  /* istanbul ignore next */
  [inspect.custom]() {
    return `${this.constructor.name} ${inspect(this.#response, {
      depth: Infinity,
      colors: process.stdout.isTTY,
      compact: false,
      sorted: true,
    })}`;
  }
}

module.exports = DeviceFlowHandle;
