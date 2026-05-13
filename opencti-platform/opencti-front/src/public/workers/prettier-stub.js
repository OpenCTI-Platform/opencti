// Prettier is an optional peer dep of monaco-graphql (used only for "format document").
// Prettier v3 uses dynamic imports internally which are incompatible with esbuild's
// IIFE bundle format. This stub replaces all prettier imports with no-ops so the
// graphql.worker.js bundle stays functional. Formatting is simply disabled.
module.exports = {};
