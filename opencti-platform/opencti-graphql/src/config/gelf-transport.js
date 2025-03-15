/* eslint-disable */

/*
 * This is a straight copy of https://github.com/fchristle/winston-gelf/blob/5420e52bc6a9830dc4a56494097c752fddcfcabc/index.js
 * with a single change, noted below.
 * We disable the eslint rules that would cause warnings in the original code.
 */

const Transport = require('winston-transport');
const logger = require('gelf-pro');

const levels = {
  emerg: 'emergency',
  alert: 'alert',
  crit: 'critical',
  error: 'error',
  warn: 'warn',
  notice: 'notice',
  info: 'info',
  debug: 'debug',
};

class GelfTransport extends Transport {
  constructor(opts) {
    super(opts);
    this.logger = Object.create(logger);
    this.logger.setConfig(opts.gelfPro);
  }

  log({ level, message, ...extra }, callback) {
    setImmediate(() => {
      this.emit('logged', { level, message, extra });
    });

    if (typeof extra === 'object') {
      for (const key in extra) {
        const value = extra[key];
        if (value instanceof Error) {
          extra = value;
        }
      }
    }

    const graylogLevel = levels[level] || levels.info;
    // CHANGE: use "callback" as the callback of the logging function
    this.logger[graylogLevel](message, extra, () => callback());
  }

  setConfig(opts) {
    this.logger.setConfig(opts.gelfPro);
  }
}

module.exports = exports = GelfTransport;
