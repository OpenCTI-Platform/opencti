import { UserInputError } from 'apollo-server-errors';
import { riskSingularizeSchema } from '../../risk-mappings.js';
import { selectComponentByIriQuery, convertAssetToComponent } from '../resolvers/sparql-query.js';


export const findComponentByIri = async (iri, dbName, dataSources, select) => {
  const sparqlQuery = selectComponentByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select Component",
      singularizeSchema: riskSingularizeSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) return null;
  const component = convertAssetToComponent(response[0]);
  return component;
}
