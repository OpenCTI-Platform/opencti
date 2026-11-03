// The default pdfjs build relies on Map.prototype.getOrInsertComputed, missing from Firefox ESR 140
const legacyPaths = {
    'pdfjs-dist': 'pdfjs-dist/legacy/build/pdf.mjs',
    'pdfjs-dist/web/pdf_viewer.mjs': 'pdfjs-dist/legacy/web/pdf_viewer.mjs',
};

module.exports.PdfjsLegacyPlugin = {
    name: 'pdfjs-legacy',
    setup: (build) => {
        build.onResolve({filter: /^pdfjs-dist(\/web\/pdf_viewer\.mjs)?$/}, (args) => build.resolve(legacyPaths[args.path], {
            kind: args.kind,
            importer: args.importer,
            resolveDir: args.resolveDir,
        }));
    },
};
