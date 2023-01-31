import { UserInputError } from 'apollo-server-express';
import { riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import { compareValues, updateQuery, filterValues } from '../../../utils.js';
import {
  getReducer,
  insertInventoryItemQuery,
  selectInventoryItemQuery,
  selectInventoryItemByIriQuery,
  selectAllInventoryItems,
  deleteInventoryItemQuery,
  deleteInventoryItemByIriQuery,
  attachToInventoryItemQuery,
  detachFromInventoryItemQuery,
  convertAssetToInventoryItem,
} from './sparql-query.js';

const inventoryItemResolvers = {
  Query: {
    inventoryItemList: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllInventoryItems(selectMap.getNode('node'), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: 'Select Inventory Item List',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      // no Inventory Items found
      if (response === undefined) return null;

      // Handle reporting Stardog Error
      if (typeof response === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      }

      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        // const reducer = getReducer("INVENTORY-ITEM");
        let filterCount;
        let resultCount;
        let limit;
        let offset;
        let limitSize;
        let offsetSize;
        limitSize = limit = args.first === undefined ? response.length : args.first;
        offsetSize = offset = args.offset === undefined ? 0 : args.offset;
        filterCount = 0;

        let inventoryItemList;
        if (args.orderedBy !== undefined) {
          inventoryItemList = response.sort(compareValues(args.orderedBy, args.orderMode));
        } else {
          inventoryItemList = response;
        }

        if (offset > inventoryItemList.length) return null;

        // for each POAM in the result set
        for (let inventoryItem of inventoryItemList) {
          // skip down past the offset
          if (offset) {
            offset--;
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(inventoryItem, args.filters, args.filterMode)) {
              continue;
            }
            filterCount++;
          }

          // convert the asset into a component
          inventoryItem = convertAssetToInventoryItem(inventoryItem);

          // if haven't reached limit to be returned
          if (limit) {
            const edge = {
              cursor: inventoryItem.iri,
              node: inventoryItem,
              // node: reducer(inventoryItem),
            };
            edges.push(edge);
            limit--;
            if (limit === 0) break;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0) return null;
        let hasNextPage = false;
        let hasPreviousPage = false;
        resultCount = inventoryItemList.length;
        if (edges.length < resultCount) {
          if (edges.length === limitSize && filterCount <= limitSize) {
            hasNextPage = true;
            if (offsetSize > 0) hasPreviousPage = true;
          }
          if (edges.length <= limitSize) {
            if (filterCount !== edges.length) hasNextPage = true;
            if (filterCount > 0 && offsetSize > 0) hasPreviousPage = true;
          }
        }
        return {
          pageInfo: {
            startCursor: edges[0].cursor,
            endCursor: edges[edges.length - 1].cursor,
            hasNextPage,
            hasPreviousPage,
            globalCount: resultCount,
          },
          edges,
        };
      }
    },
    inventoryItem: async (_, { id }, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectInventoryItemQuery(id, selectMap.getNode('inventoryItem'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select Inventory Item',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      // Handle reporting Stardog Error
      if (typeof response === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      }

      if (Array.isArray(response) && response.length > 0) {
        // convert the asset into a component
        return convertAssetToInventoryItem(response[0]);
      }
    },
  },
  Mutation: {
    createInventoryItem: async (_, { input }, { dbName, selectMap, dataSources }) => {},
    deleteInventoryItem: async (_, { id }, { dbName, dataSources }) => {},
    editInventoryItem: async (_, { id, input }, { dbName, dataSources, selectMap }) => {},
  },
  InventoryItem: {
    labels: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.labels_iri === undefined) return [];
      const iriArray = parent.labels_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer('LABEL');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Label')) continue;
          const sparqlQuery = selectLabelByIriQuery(iri, selectMap.getNode('labels'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Label',
              singularizeSchema,
            });
          } catch (e) {
            console.log(e);
            throw e;
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]));
          } else {
            // Handle reporting Stardog Error
            if (typeof response === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: response.body.message ? response.body.message : response.body,
                error_code: response.body.code ? response.body.code : 'N/A',
              });
            }
          }
        }
        return results;
      }
      return [];
    },
    links: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.links_iri === undefined) return [];
      const iriArray = parent.links_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer('EXTERNAL-REFERENCE');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('ExternalReference')) continue;
          const sparqlQuery = selectExternalReferenceByIriQuery(iri, selectMap.getNode('links'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select External Reference',
              singularizeSchema,
            });
          } catch (e) {
            console.log(e);
            throw e;
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]));
          } else {
            // Handle reporting Stardog Error
            if (typeof response === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: response.body.message ? response.body.message : response.body,
                error_code: response.body.code ? response.body.code : 'N/A',
              });
            }
          }
        }
        return results;
      }
      return [];
    },
    remarks: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.remarks_iri === undefined) return [];
      const iriArray = parent.remarks_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer('NOTE');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Note')) continue;
          const sparqlQuery = selectNoteByIriQuery(iri, selectMap.getNode('remarks'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Note',
              singularizeSchema,
            });
          } catch (e) {
            console.log(e);
            throw e;
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]));
          } else {
            // Handle reporting Stardog Error
            if (typeof response === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: response.body.message ? response.body.message : response.body,
                error_code: response.body.code ? response.body.code : 'N/A',
              });
            }
          }
        }
        return results;
      }
      return [];
    },
    responsible_parties: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.responsible_parties_iri === undefined) return [];
      const reducer = getCommonReducer('RESPONSIBLE-PARTY');
      const results = [];
      const sparqlQuery = selectAllResponsibleParties(selectMap.getNode('node'), args, parent);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select Referenced Responsible Parties',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      if (response === undefined || response.length === 0) return null;

      // Handle reporting Stardog Error
      if (typeof response === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      }

      for (const item of response) {
        results.push(reducer(item));
      }

      // check if there is data to be returned
      if (results.length === 0) return [];
      return results;
    },
    implemented_components: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.implemented_components !== undefined) return parent.implemented_components;
      if (parent.implemented_components_iri === undefined) return [];
    },
  },
};

export default inventoryItemResolvers;
