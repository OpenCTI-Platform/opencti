import { UserInputError } from 'apollo-server-errors';
// TODO: replace with the oscalRemark sparql schema file
import { riskSingularizeSchema } from '../../risk-mappings.js';
// TODO: create a separate scheme file for oscalRemark to replace
//       the use of Note
import { selectNoteByIriQuery, getReducer } from '../../../global/resolvers/sparql-query.js';
// import { 
//   getReducer,
//   singularizeOscalRemarkSchema,
//   selectRemarkByIriQuery,
// } from '../schema/sparql/oscalRemark.js';


export const findLinkByIri = async (iri, dbName, dataSources, select) => {
  const sparqlQuery = selectNoteByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select Remark",
      singularizeSchema: riskSingularizeSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) return null;
  let reducer = getReducer('NOTE');
  return reducer(response[0]);
}
