import { UserInputError } from 'apollo-server-errors';
// TODO: replace with the oscalParty sparql schema file
import { riskSingularizeSchema } from '../../risk-mappings.js';
// TODO: create a separate scheme file for oscalRole to replace
//       the use of sparql-query
import { selectRoleByIriQuery, getReducer } from '../resolvers/sparql-query.js';
// import { 
//   getReducer,
//   singularizeOscalRoleSchema,
//   selectRoleByIriQuery,
// } from '../schema/sparql/oscalRole.js';


export const findRoleByIri = async (iri, dbName, dataSources, select) => {
  const sparqlQuery = selectRoleByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select Role",
      singularizeSchema: riskSingularizeSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) return null;
  let reducer = getReducer('ROLE');
  return reducer(response[0]);
}
