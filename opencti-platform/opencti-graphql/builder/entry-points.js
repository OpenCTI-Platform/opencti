// Shared with knip.ts, which needs the same list. Kept out of builder.js because that
// module runs esbuild on import.
export const BUILD_ENTRY_POINTS = [
  'src/back.ts',
  'src/lock/child-lock.manager.ts',
  'script/script-clean-relations.js',
  'script/script-insert-dataset.js',
  'src/utils/safeEjs.worker.ts',
];
