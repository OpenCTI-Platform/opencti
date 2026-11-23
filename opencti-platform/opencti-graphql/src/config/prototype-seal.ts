// Bundled ahead of every backend entry point by esbuild (BUILD_INJECTED_MODULES in builder/entry-points.ts): each thread or
// process has its own Object.prototype, and it is sealed before any dependency loads, so none can add a property to it.
// Sealed rather than frozen: its existing members stay writable, as dependencies (moment, ipaddr.js, bluebird...) assign
// toString, valueOf or constructor on their own prototypes, which throws in strict mode once Object.prototype is frozen.
Object.seal(Object.prototype);
