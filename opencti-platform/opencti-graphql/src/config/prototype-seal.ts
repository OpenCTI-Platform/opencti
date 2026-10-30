// Imported first by every backend entry point (platform, lock child process, safeEjs worker), as each thread or process has its
// own Object.prototype. Imported before any dependency loads: no property can be added to Object.prototype afterwards.
// Sealed rather than frozen: its existing members stay writable, as dependencies (moment, ipaddr.js, bluebird...) assign
// toString, valueOf or constructor on their own prototypes, which throws in strict mode once Object.prototype is frozen.
Object.seal(Object.prototype);
