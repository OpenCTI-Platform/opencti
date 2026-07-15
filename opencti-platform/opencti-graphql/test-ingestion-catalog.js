// autocannon-ingestion-catalog.js
const autocannon = require('autocannon');

const TOKEN = process.env.OPENCTI_TOKEN;

const QUERY = `
  query IngestionConnectorsCatalogsQuery {
    catalogs {
      id
      name
      description
      contracts
    }
  }
`;

const body = JSON.stringify({
  operationName: 'IngestionConnectorsCatalogsQuery',
  query: QUERY,
  variables: {}
});

autocannon({
  url: 'http://localhost:4000/graphql',
  connections: 100,     // concurrency knob — try 50 / 100 / 200
  pipelining: 1,
  duration: 120,        // seconds
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    'authorization': `Bearer ${TOKEN}`
  },
  body
}, (err, result) => {
  if (err) return console.error(err);
  console.log(autocannon.printResult(result));
  console.log(`\nnon-2xx errors: ${result.non2xx}, timeouts: ${result.timeouts}, errors: ${result.errors}`);
});