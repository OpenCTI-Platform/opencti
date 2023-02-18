import { UserInputError } from 'apollo-server-errors';
import { riskSingularizeSchema } from '../../risk-mappings.js';
import { selectInventoryItemByIriQuery, convertAssetToInventoryItem } from '../resolvers/sparql-query.js';


export const findInventoryItemByIri = async (iri, dbName, dataSources, select) => {
  const sparqlQuery = selectInventoryItemByIriQuery(iri, select);
  let response;
  try {
    response = await dataSources.Stardog.queryById({
      dbName,
      sparqlQuery,
      queryId: "Select Inventory ITem",
      singularizeSchema: riskSingularizeSchema
    });
  } catch (e) {
    console.log(e)
    throw e
  }
  if (response === undefined || response === null || response.length === 0) return null;
  const inventoryItem = convertAssetToInventoryItem(response[0]);
  return inventoryItem;
}
