import fs from 'node:fs/promises';
import { printSchema } from 'graphql';
import '../src/modules/index';
import createSchema from '../src/graphql/schema';

const schema = createSchema();
const printedSchema = printSchema(schema);
await fs.writeFile('../opencti-front/src/schema/relay.schema.graphql', printedSchema);
