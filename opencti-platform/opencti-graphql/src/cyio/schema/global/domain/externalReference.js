import { UserInputError } from 'apollo-server-errors';
// TODO: move all query builder exports to the externalReference sparql schema file
import { selectExternalReferenceByIriQuery } from '../resolvers/sparql-query.js';
import { 
  getReducer,
  singularizeExternalReferenceSchema,
//   selectExternalReferenceByIriQuery,
} from '../schema/sparql/externalReference.js';


export const findExternalReferenceByIri = async (iri, dbName, dataSources, select) => {
  const sparqlQuery = selectExternalReferenceByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select External Reference",
      singularizeSchema: singularizeExternalReferenceSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) return null;
  let reducer = getReducer('EXTERNAL-REFERENCE');
  return reducer(response[0]);
}
