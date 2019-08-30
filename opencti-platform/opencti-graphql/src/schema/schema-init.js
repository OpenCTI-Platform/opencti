import { write } from '../database/grakn';
import { createIndexes, elasticIsAlive } from '../database/elasticSearch';

const fs = require('fs');

elasticIsAlive().then(async () => {
  await createIndexes();
  const schema = fs.readFileSync('./src/opencti.gql', 'utf8');
  write(schema).then(() => {
    process.exit(0);
  });
});
