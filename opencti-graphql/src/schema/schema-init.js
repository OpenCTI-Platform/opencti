import { write } from '../database/grakn';

const fs = require('fs');

const schema = fs.readFileSync('./src/stix2.gql', 'utf8');
write(schema);
