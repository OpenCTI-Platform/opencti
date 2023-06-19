/* eslint-disable */
// noinspection ES6UnusedImports,ES6CheckImport

import fs, {mkdir} from 'node:fs';
import {printSchema} from 'graphql/utilities';
import createSchema from '../src/graphql/schema';
import _ from '../src/modules/index';

const schema = createSchema();
const printedSchema = printSchema(schema);

try {
  fs.mkdirSync('../opencti-front/src/schema/');
} catch (error) {
  if (!(error.message.startsWith("EEXIST"))) {
    throw error;
  }
}

fs.writeFileSync('../opencti-front/src/schema/relay.schema.graphql', printedSchema);
