const {Converter} = require("sparqljson-to-tree/lib/Converter");
const {query, Connection} = require("stardog");
const {expect} = require("jest")
const fs = require("fs")
const path = require("path")
require('dotenv').config();

function readFile(fileName) {
  return fs.readFileSync(path.join(__dirname, fileName), {encoding: "utf-8"})
}

class IntegrityRunner {
  constructor() {
    const endpoint = process.env.TESTING_SD_ENDPOINT;
    const username = process.env.TESTING_SD_USERNAME;
    const password = process.env.TESTING_SD_PASSWORD;
    this.database = process.env.TESTING_SD_DATABASE;
    this.connection = new Connection({endpoint, password, username});
  }

  runCheck({config, singularizeSchema = null}) {
    test(config.describe, () => {
      return query.execute(this.connection, this.database, readFile(`${config.root}/query/${config.test}.rq`), 'application/sparql-results+json')
        .then((response) => {
            const sparqlResponse = response.body;
            if (response.status !== 200 ) {
              throw new Error(response.statusText)
            }
            const converter = new Converter({
              delimiter: '-',
              materializeRdfJsTerms: true,
            });
            if(sparqlResponse == null) return null;
            const data = converter.sparqlJsonResultsToTree( sparqlResponse, singularizeSchema)
            const expected = readFile(`./${config}.json`)
            expect(data).toEqual(expected)
        })
    })
  }
}

export default IntegrityRunner

