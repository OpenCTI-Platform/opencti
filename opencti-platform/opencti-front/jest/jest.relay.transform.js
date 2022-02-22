const fs = require("fs");
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
  process(src, filename, ...rest) {
    let contents = fs.readFileSync(filename, { encoding: "UTF-8" })
    if (!filename.includes('node_modules') && !filename.includes('__generated__')) {
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
    return t.process(contents, filename, ...rest);
  },
};
