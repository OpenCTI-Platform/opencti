import { UserInputError } from 'apollo-server-errors';
// TODO: replace with the OscalLink sparql schema file
import { riskSingularizeSchema } from '../../risk-mappings.js';
// TODO: create a separate scheme file for oscalLink to replace
//       the use of ExternalReference
import { selectExternalReferenceByIriQuery, getReducer } from '../../../global/resolvers/sparql-query.js';
// import { 
//   getReducer,
//   singularizeOscalLinkSchema,
//   selectLinkByIriQuery,
// } from '../schema/sparql/oscalLink.js';

export const findLinkByIri = async (iri, dbName, dataSources, select) => {
  const sparqlQuery = selectExternalReferenceByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select Link",
      singularizeSchema: riskSingularizeSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) return null;
  let reducer = getReducer('EXTERNAL-REFERENCE');
  return reducer(response[0]);
}
