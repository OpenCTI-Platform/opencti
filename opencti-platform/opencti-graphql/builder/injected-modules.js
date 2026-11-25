// Bundled ahead of every entry point's own code (esbuild `inject`) by the dev and prod builds, so no entry point can
// forget them or have them moved down by an import sort. Kept out of the builders because they run esbuild on require,
// and the prototype seal test needs this list.
module.exports = {
  BUILD_INJECTED_MODULES: [
    'src/config/prototype-seal.ts',
  ],
};
