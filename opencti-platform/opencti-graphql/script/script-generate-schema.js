/* eslint-disable */
// noinspection ES6UnusedImports,ES6CheckImport

import fs from 'node:fs';
import { printSchema } from 'graphql/utilities';
import createSchema from '../src/graphql/schema';
import _ from '../src/modules/index';

const schema = createSchema();
const printedSchema = printSchema(schema);
fs.writeFileSync('../opencti-front/src/schema/relay.schema.graphql', printedSchema);
