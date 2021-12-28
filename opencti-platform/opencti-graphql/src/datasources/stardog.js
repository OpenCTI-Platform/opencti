import { DataSource } from 'apollo-datasource'
import { InMemoryLRUCache } from 'apollo-server-caching';
import { Converter as TreeConverter } from 'sparqljson-to-tree';
import conf from '../config/conf';

// A bit of hackery because of how Stardog exported the query 
import pkg from 'stardog';
import {ApolloError} from "apollo-errors";
const { query, Connection } = pkg;

export class StardogError extends ApolloError {
  constructor(response, message, query) {
    super("StardogError", {
      message,
      time_thrown: new Date(), // UTC
      internalData: { // Is not included when sent to client, internal use only
        response_status: response.statusText,
        response_message: response.body,
        query
      }
    })
  }
}

const throwFailed = (response, message, query) => {
  if(response.status > 299){
    throw new StardogError(response, message, query)
  }
}

export default class Stardog extends DataSource {
  constructor(  ) {
    super()

    const endpoint = conf.get('stardog:endpoint');
    const username = conf.get('stardog:username');
    const password = conf.get('stardog:password');
    const conn = new Connection({
      endpoint: endpoint,
      username: username,
      password: password
      } );
    this.conn = conn
  }

  // 
  // This is a function that gets called by ApolloServer when being setup.
  // This function gets called with the datasource config including things
  // like caches and context.  Assign this.context to the request context
  // here, so we can know about the user making requests
  //
  initialize( config ) {
    this.context = config.context ;
    this.cache = config.cache || new InMemoryLRUCache()
  }

  async queryById( dbName, sparqlQuery, singularizeSchema ) {
    return await query.execute( this.conn, dbName, sparqlQuery, 'application/sparql-results+json', 
    ).then (function (response) {
      console.log(response);
      const sparqlResponse = response.body;
      const converter = new TreeConverter({
        // The string to split variable names by. 
        delimiter: '-',
        // If terms should be converted to their raw value instead of being represented as RDFJS terms
        materializeRdfJsTerms: true,
      });

      //return SPARQL error response if not successful
      if (response.status !== 200 ) {
        return response
      }

      if(sparqlResponse == null) return null;
      // convert the SPARQL results to JavaScript dictionary
      var results = converter.sparqlJsonResultsToTree( sparqlResponse, singularizeSchema );
      return results;
    })
    .catch (function (error) {
      console.log(error);
    });
  }

  async queryAll( dbName, sparqlQuery, singularizeSchema, limitValue, offsetValue, ) {
    let params = { reasoning: false };
    if (limitValue !== undefined) params['limit'] =  limitValue
    if (offsetValue !== undefined) params['offset'] = offsetValue

    return await query.execute( this.conn, dbName, sparqlQuery, 'application/sparql-results+json', params, 
    ).then (function (response) {
      console.log(response);
      const sparqlResponse = response.body;
      const converter = new TreeConverter({
        // The string to split variable names by. 
        delimiter: '-',
        // If terms should be converted to their raw value instead of being represented as RDFJS terms
        materializeRdfJsTerms: true,
      });

      //return SPARQL error response if not successful
      if (response.status !== 200 ) {
        return response
      }

      // convert the SPARQL results to JavaScript dictionary
      var results = converter.sparqlJsonResultsToTree( sparqlResponse, singularizeSchema );
      return results;
    })
    .catch (function (error) {
      console.log(error);
    });
  }

  async create( dbName, sparqlQuery, queryId ) {
    const response = await query.execute( this.conn, dbName, sparqlQuery, 'text/turtle', {
      reasoning: false,
    }).catch((err) => {
      console.log(err)
      throw err;
    });
    throwFailed(response, `Failed to execute insert query '${queryId}'`, sparqlQuery);
    return response;
  }

  async delete( dbName, sparqlQuery, queryId) {
    const response = query.execute( this.conn, dbName, sparqlQuery, 'text/turtle', {
      reasoning: false,
    }).catch((err) => {
      console.log(err)
      throw err;
    });
    throwFailed(response, `Failed to execute delete query '${queryId}'`, sparqlQuery)
    return response;
  }
  async edit( dbName, sparqlQuery, queryId ) {
    const response = query.execute( this.conn, dbName, sparqlQuery, 'text/turtle', {
      reasoning: false,
    }).catch((err) => {
      console.log(err)
      throw err;
    });
    throwFailed(response, `Failed to execute update query '${queryId}'`, sparqlQuery)
    return response;
  }
}
