module.exports = globalThis.structuredClone || ((obj) => JSON.parse(JSON.stringify(obj)));
