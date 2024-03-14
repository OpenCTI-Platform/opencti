const { STATUS_CODES } = require('http');
const { format } = require('util');

const { OPError } = require('../errors');
const parseWwwAuthenticate = require('./www_authenticate_parser');

const throwAuthenticateErrors = (response) => {
  const params = parseWwwAuthenticate(response.headers['www-authenticate']);

  if (params.error) {
    throw new OPError(params, response);
  }
};

const isStandardBodyError = (response) => {
  let result = false;
  try {
    let jsonbody;
    if (typeof response.body !== 'object' || Buffer.isBuffer(response.body)) {
      jsonbody = JSON.parse(response.body);
    } else {
      jsonbody = response.body;
    }
    result = typeof jsonbody.error === 'string' && jsonbody.error.length;
    if (result) Object.defineProperty(response, 'body', { value: jsonbody, configurable: true });
  } catch (err) {}

  return result;
};

function processResponse(response, { statusCode = 200, body = true, bearer = false } = {}) {
  if (response.statusCode !== statusCode) {
    if (bearer) {
      throwAuthenticateErrors(response);
    }

    if (isStandardBodyError(response)) {
      throw new OPError(response.body, response);
    }

    throw new OPError(
      {
        error: format(
          'expected %i %s, got: %i %s',
          statusCode,
          STATUS_CODES[statusCode],
          response.statusCode,
          STATUS_CODES[response.statusCode],
        ),
      },
      response,
    );
  }

  if (body && !response.body) {
    throw new OPError(
      {
        error: format(
          'expected %i %s with body but no body was returned',
          statusCode,
          STATUS_CODES[statusCode],
        ),
      },
      response,
    );
  }

  return response.body;
}

module.exports = processResponse;
