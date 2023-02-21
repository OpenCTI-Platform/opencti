import { UserInputError } from 'apollo-server-errors';
// TODO: replace with the oscalParty sparql schema file
import { riskSingularizeSchema } from '../../risk-mappings.js';
// TODO: create a separate scheme file for oscalLink to replace
//       the use of oscalParty
import { selectPartyByIriQuery, getReducer } from '../resolvers/sparql-query.js';
// import { 
//   getReducer,
//   singularizeOscalPartySchema,
//   selectPartyByIriQuery,
// } from '../schema/sparql/oscalParty.js';


export const findPartyByIri = async (iri, dbName, dataSources, select) => {
  const sparqlQuery = selectPartyByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select Party",
      singularizeSchema: riskSingularizeSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) return null;
  let reducer = getReducer('PARTY');
  return reducer(response[0]);
}
