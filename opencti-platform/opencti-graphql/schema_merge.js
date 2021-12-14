const join = require('path').join;
const loadFilesSync = require("@graphql-tools/load-files").loadFilesSync;
const mergeTypeDefs = require("@graphql-tools/merge").mergeTypeDefs;
const print = require('graphql').print;
const fs = require('fs');

const schemaFiles = loadFilesSync(join(__dirname, '**/*.graphql'));
const uiFiles = loadFilesSync(join(__dirname, '../opencti-front/**/*.graphql'));
const files = schemaFiles.concat(uiFiles);
const mergedTypeDefs = mergeTypeDefs(files);
const printed = print(mergedTypeDefs);
fs.writeFileSync(join(__dirname, 'config/schema/compiled.graphql'), printed);
