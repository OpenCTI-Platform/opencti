import { UserInputError } from 'apollo-server-errors';
// TODO: move all query builder exports to the label sparql schema file
import { selectLabelByIriQuery } from '../resolvers/sparql-query.js';
import { 
  getReducer,
  singularizeLabelSchema,
//   selectLabelByIriQuery,
} from '../schema/sparql/label.js';


export const findLabelByIri = async (iri, dbName, dataSources, select) => {
  const sparqlQuery = selectLabelByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select Label",
      singularizeSchema: singularizeLabelSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) return null;
  let reducer = getReducer('LABEL');
  return reducer(response[0]);
}
