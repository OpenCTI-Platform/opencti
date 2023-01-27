import { DataSource } from 'apollo-datasource';
import { InMemoryLRUCache } from 'apollo-server-caching';
import { Converter as TreeConverter } from 'sparqljson-to-tree';

// A bit of hackery because of how Stardog exported the query
import pkg from 'stardog';
import { ApolloError } from 'apollo-errors';
import conf from '../config/conf';

const { query, Connection } = pkg;

export class StardogError extends ApolloError {
  constructor(db, response, message, query) {
    super('StardogError', {
      db,
      message,
      time_thrown: new Date(), // UTC
      internalData: {
        // Is not included when sent to client, internal use only
        response_status: response.statusText,
        response_message: response.body,
        query,
      },
    });
  }
}

const throwFailed = (db, response, message, query) => {
  if (response.status > 299) {
    throw new StardogError(db, response, message, query);
  }
};

export default class Stardog extends DataSource {
  constructor() {
    super();

    const endpoint = conf.get('stardog:endpoint');
    const username = conf.get('stardog:username');
    const password = conf.get('stardog:password');
    const conn = new Connection({
      endpoint,
      username,
      password,
    });
    this.conn = conn;
  }

  //
  // This is a function that gets called by ApolloServer when being setup.
  // This function gets called with the datasource config including things
  // like caches and context.  Assign this.context to the request context
  // here, so we can know about the user making requests
  //
  initialize(config) {
    this.context = config.context;
    this.cache = config.cache || new InMemoryLRUCache();
  }

  /**
   *
   * @param options object with parameters for query
   * @returns {Promise<*>}
   */
  async queryById({ dbName, sparqlQuery, queryId = "'not-specified'", singularizeSchema }) {
    const response = await query
      .execute(this.conn, dbName, sparqlQuery, 'application/sparql-results+json')
      .catch((err) => {
        console.log(err);
        throw err;
      });

    throwFailed(dbName, response, `Failed to execute query ${queryId}`, sparqlQuery);

    const sparqlResponse = response.body;
    const converter = new TreeConverter({
      // The string to split variable names by.
      delimiter: '-',
      // If terms should be converted to their raw value instead of being represented as RDFJS terms
      materializeRdfJsTerms: true,
    });

    // return SPARQL error response if not successful
    if (response.status !== 200) {
      return response;
    }

    if (sparqlResponse == null) return null;
    // convert the SPARQL results to JavaScript dictionary
    const results = converter.sparqlJsonResultsToTree(sparqlResponse, singularizeSchema);
    return results;
  }

  // singularizeSchema, limitValue, offsetValue
  async queryAll({ dbName, sparqlQuery, queryId = "'not-specified'", limitValue, offsetValue, singularizeSchema }) {
    const params = { reasoning: false };
    if (limitValue !== undefined) params.limit = limitValue;
    if (offsetValue !== undefined) params.offset = offsetValue;

    const response = await query
      .execute(this.conn, dbName, sparqlQuery, 'application/sparql-results+json', params)
      .catch((err) => {
        console.log(err);
        throw err;
      });

    throwFailed(dbName, response, `Failed to execute query ${queryId}`, sparqlQuery);

    const sparqlResponse = response.body;
    const converter = new TreeConverter({
      // The string to split variable names by.
      delimiter: '-',
      // If terms should be converted to their raw value instead of being represented as RDFJS terms
      materializeRdfJsTerms: true,
    });

    // convert the SPARQL results to JavaScript dictionary
    return converter.sparqlJsonResultsToTree(sparqlResponse, singularizeSchema);
  }

  async create({ dbName, sparqlQuery, queryId }) {
    const response = await query
      .execute(this.conn, dbName, sparqlQuery, 'text/turtle', {
        reasoning: false,
      })
      .catch((err) => {
        console.log(err);
        throw err;
      });
    throwFailed(dbName, response, `Failed to execute insert query '${queryId}'`, sparqlQuery);
    return response;
  }

  async delete({ dbName, sparqlQuery, queryId }) {
    const response = query
      .execute(this.conn, dbName, sparqlQuery, 'text/turtle', {
        reasoning: false,
      })
      .catch((err) => {
        console.log(err);
        throw err;
      });
    throwFailed(dbName, response, `Failed to execute delete query '${queryId}'`, sparqlQuery);
    return response;
  }

  async edit({ dbName, sparqlQuery, queryId }) {
    const response = query
      .execute(this.conn, dbName, sparqlQuery, 'text/turtle', {
        reasoning: false,
      })
      .catch((err) => {
        console.log(err);
        throw err;
      });
    throwFailed(dbName, response, `Failed to execute update query '${queryId}'`, sparqlQuery);
    return response;
  }
}
