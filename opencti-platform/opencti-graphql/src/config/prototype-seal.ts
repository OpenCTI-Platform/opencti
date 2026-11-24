// Bundled ahead of every backend entry point by esbuild (BUILD_INJECTED_MODULES in builder/entry-points.ts): each thread or
// process has its own built-in prototypes, and they are sealed before any dependency loads, so none can add a property to them.
// Sealed rather than frozen: their existing members stay writable, as dependencies (moment, ipaddr.js, bluebird...) assign
// toString, valueOf or constructor on their own prototypes, which throws in strict mode once the inherited member is frozen.
// The constructors (Object, Array...) and globalThis stay open: a static property changes no lookup on instances, and some
// libraries define globals when they load.
[
  // Reachable by any JSON payload through a merge or set helper.
  Object.prototype,
  Array.prototype,
  // Defence in depth: reachable only when a helper walks into a primitive, a function or a non-JSON object.
  String.prototype,
  Number.prototype,
  Boolean.prototype,
  Symbol.prototype,
  BigInt.prototype,
  Function.prototype,
  RegExp.prototype,
  Date.prototype,
  Error.prototype,
  Promise.prototype,
  Map.prototype,
  Set.prototype,
  WeakMap.prototype,
  WeakSet.prototype,
].forEach((prototype) => Object.seal(prototype));
