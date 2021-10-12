import { DataSource } from 'apollo-datasource'
import { InMemoryLRUCache } from 'apollo-server-caching'

const  { query } = require('stardog')

class StardogDataSource extends DataSource {
  constructor(stardogConnection) {
    super()
    this.conn = stardogConnection
  }

  initialize( { context, cache } = {}) {
    this.context = context
    this.cache = cache || new InMemoryLRUCache()
  }

  didEncounterError( error ) {
    throw error
  }

  async queryKB( dbName, queryStr, limitValue, offsetValue ) {
    query.execute( this.conn, dbName, queryStr, 'application/sparql-results+json', {
      limit: limitValue,
      reasoning: false,
      offset: offsetValue,
    }).then(({ body }) => {
      return(body.results.bindings);
    });
  }

  async updateKB( dbName, queryStr ) {
    query.execute( this.conn, dbName, queryStr, 'text/turtle', {
      reasoning: false,
    }).then(( {body }) => {
      return(body.results.bindings);
    });
  }
}