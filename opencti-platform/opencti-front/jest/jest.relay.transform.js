'use strict';

const {print, parse} = require("graphql");
const crypto = require("crypto");
const transformer = require("esbuild-jest");

const t = transformer.createTransformer({
  sourcemap: true,
  loaders: {
    '.js': 'jsx',
    '.svg': 'dataurl',
    '.png': 'dataurl',
    '.woff': 'dataurl',
    '.woff2': 'dataurl',
    '.ttf': 'dataurl'
  }
})

module.exports = {
  process(sourceText, sourcePath, options) {
    let contents = sourceText;
    if (!sourcePath.includes('__generated__')) {
      // console.log(sourcePath);
      if (contents.includes('graphql`')) {
        const imports = [];
        contents = contents.replaceAll(/\sgraphql`([\s\S]*?)`/gm, (match, query) => {
          const formatted = print(parse(query));
          const name = /(fragment|mutation|query|subscription) (\w+)/.exec(formatted)[2];
          const id = `graphql__${crypto.randomBytes(10).toString('hex')}`;
          const importFile = `import ${id} from "./__generated__/${name}.graphql";`;
          imports.push(importFile);
          return id;
        });
        contents = imports.join('\n') + contents;
      }
    }
    return t.process(contents, sourcePath, options);
  },
};
