import { write } from '../database/grakn';

const fs = require('fs');

const schema = fs.readFileSync('./src/stix2_clear_rules.gql', 'utf8');
write(schema).then(() => {
  process.exit(0);
});
