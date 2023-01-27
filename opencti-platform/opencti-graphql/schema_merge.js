const { join } = require('path');
const { loadFilesSync } = require('@graphql-tools/load-files');
const { mergeTypeDefs } = require('@graphql-tools/merge');
const { print } = require('graphql');
const fs = require('fs');

const schemaFiles = loadFilesSync(join(__dirname, '**/*.graphql'));
// if (schemaFiles.length == 0) throw new Error('no runtime GraphQL schema files found...');
const uiFiles = loadFilesSync(join(__dirname, '../opencti-front/**/*.graphql'));
// if (uiFiles.length == 0) throw new Error('no UI GraphQL schema files found...');
const files = schemaFiles.concat(uiFiles);
const mergedTypeDefs = mergeTypeDefs(files);
const printed = print(mergedTypeDefs);
fs.writeFileSync(join(__dirname, 'config/schema/compiled.graphql'), printed);
