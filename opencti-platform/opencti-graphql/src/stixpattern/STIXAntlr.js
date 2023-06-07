// Require for esbuild to generate a clean bundle
// Class cjs import will also include meta.import.url that is not supported by esbuild
const antlr4 = require('antlr4');
antlr4.atn = antlr4;
antlr4.dfa = antlr4;
antlr4.error = antlr4;
antlr4.tree = antlr4;

export default antlr4;