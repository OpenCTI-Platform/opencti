const {promises} = require('fs');
const crypto = require('crypto');
const {print, parse} = require('graphql');

module.exports.RelayPlugin = {
    name: 'relay',
    setup: (build) => {
        build.onLoad({filter: /\.(js)$/, namespace: "file"}, async (args) => {
            let contents = await promises.readFile(args.path, 'utf8');
            if (!args.path.includes('node_modules') && !args.path.includes('__generated__')) {
                if (contents.includes('graphql`')) {
                    const imports = [];
                    contents = contents.replaceAll(/\sgraphql`([\s\S]*?)`/gm, (match, query) => {
                        const formatted = print(parse(query));
                        const graphLineExtra = formatted.split("\n").map(() => "\n").join(""); // Need for debug alignment
                        const name = /(fragment|mutation|query|subscription) (\w+)/.exec(formatted)[2];
                        const id = `graphql__${crypto.randomBytes(10).toString('hex')}`;
                        imports.push(`import ${id} from "./__generated__/${name}.graphql";`);
                        return id + graphLineExtra;
                    });
                    contents = imports.join('\n') + contents;
                }
            }
            return {
                contents,
                loader: 'jsx',
            };
        });
    },
};
