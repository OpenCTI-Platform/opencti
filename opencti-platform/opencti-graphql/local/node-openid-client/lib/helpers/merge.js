const isPlainObject = require('./is_plain_object');

function merge(target, ...sources) {
  for (const source of sources) {
    if (!isPlainObject(source)) {
      continue;
    }
    for (const [key, value] of Object.entries(source)) {
      /* istanbul ignore if */
      if (key === '__proto__' || key === 'constructor') {
        continue;
      }
      if (isPlainObject(target[key]) && isPlainObject(value)) {
        target[key] = merge(target[key], value);
      } else if (typeof value !== 'undefined') {
        target[key] = value;
      }
    }
  }

  return target;
}

module.exports = merge;
