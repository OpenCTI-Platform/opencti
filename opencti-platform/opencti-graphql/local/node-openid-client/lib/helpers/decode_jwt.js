const base64url = require('./base64url');

module.exports = (token) => {
  if (typeof token !== 'string' || !token) {
    throw new TypeError('JWT must be a string');
  }

  const { 0: header, 1: payload, 2: signature, length } = token.split('.');

  if (length === 5) {
    throw new TypeError('encrypted JWTs cannot be decoded');
  }

  if (length !== 3) {
    throw new Error('JWTs must have three components');
  }

  try {
    return {
      header: JSON.parse(base64url.decode(header)),
      payload: JSON.parse(base64url.decode(payload)),
      signature,
    };
  } catch (err) {
    throw new Error('JWT is malformed');
  }
};
