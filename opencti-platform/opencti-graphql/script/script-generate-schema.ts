import fs from 'node:fs/promises';
import { lexicographicSortSchema, printSchema } from 'graphql';
import '../src/modules/index';
import createSchema from '../src/graphql/schema';
import { registerModules } from '../src/composition-root';

registerModules();
const schema = createSchema();
// Sorted, so that the file only changes when the schema does, not when registration order does
const printedSchema = printSchema(lexicographicSortSchema(schema));
await fs.writeFile('../opencti-front/src/schema/relay.schema.graphql', printedSchema);
