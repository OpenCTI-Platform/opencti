const { createHash, randomBytes } = require('crypto');

const base64url = require('./base64url');

const random = (bytes = 32) => base64url.encode(randomBytes(bytes));

module.exports = {
  random,
  state: random,
  nonce: random,
  codeVerifier: random,
  codeChallenge: (codeVerifier) =>
    base64url.encode(createHash('sha256').update(codeVerifier).digest()),
};
