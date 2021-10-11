import StardogDataSource from './Datasources/startdog-datasource'
import { reportError } from './utils'

export default class StardogKB extends StardogDataSource {
    async queryById(dbName, sparqlQuery ) {
        const results = await this.queryKB(sparqlQuery, dbName)
        return results
    }

    async filteredQuery( dbName, sparqlQuery, limit, offset, filter ) {
        const results = await this.queryKB(sparqlQuery, dbName, limitValue, offsetValue)
        return results
    }

    async create( dbName, sparqlQuery ) {
        const results = await this.updateKB( dbname, sparqlQuery)
        return results
    }

    async delete( dbName, sparqlQuery ) {
        const results = await this.updateKB( dbname, sparqlQuery)
        return results
    }
}