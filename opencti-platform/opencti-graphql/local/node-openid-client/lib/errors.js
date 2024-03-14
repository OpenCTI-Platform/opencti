const { format } = require('util');

class OPError extends Error {
  constructor({ error_description, error, error_uri, session_state, state, scope }, response) {
    super(!error_description ? error : `${error} (${error_description})`);

    Object.assign(
      this,
      { error },
      error_description && { error_description },
      error_uri && { error_uri },
      state && { state },
      scope && { scope },
      session_state && { session_state },
    );

    if (response) {
      Object.defineProperty(this, 'response', {
        value: response,
      });
    }

    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
}

class RPError extends Error {
  constructor(...args) {
    if (typeof args[0] === 'string') {
      super(format(...args));
    } else {
      const { message, printf, response, ...rest } = args[0];
      if (printf) {
        super(format(...printf));
      } else {
        super(message);
      }
      Object.assign(this, rest);
      if (response) {
        Object.defineProperty(this, 'response', {
          value: response,
        });
      }
    }

    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
}

module.exports = {
  OPError,
  RPError,
};
