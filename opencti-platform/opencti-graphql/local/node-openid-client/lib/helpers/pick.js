module.exports = function pick(object, ...paths) {
  const obj = {};
  for (const path of paths) {
    if (object[path] !== undefined) {
      obj[path] = object[path];
    }
  }
  return obj;
};
