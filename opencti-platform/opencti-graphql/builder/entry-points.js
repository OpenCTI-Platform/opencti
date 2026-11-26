// Kept out of builder.js because that module runs esbuild on import, and the prototype seal test needs
// the injected modules.
export const BUILD_ENTRY_POINTS = [
  'src/back.ts',
  'src/lock/child-lock.manager.ts',
  'script/script-clean-relations.js',
  'script/script-insert-dataset.js',
  'src/utils/safeEjs.worker.ts',
  'src/utils/jsonPath.worker.ts',
];

// Bundled ahead of every entry point's own code (esbuild `inject`), so no entry point can forget them
// or have them moved down by an import sort.
export const BUILD_INJECTED_MODULES = [
  'src/config/prototype-seal.ts',
];
