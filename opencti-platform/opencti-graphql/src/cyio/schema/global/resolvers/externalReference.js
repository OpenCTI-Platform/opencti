import { UserInputError } from 'apollo-server-express';
import { assetSingularizeSchema as singularizeSchema } from '../../assets/asset-mappings.js';
import { compareValues, updateQuery, filterValues, CyioError } from '../../utils.js';
import {
  getReducer,
  insertExternalReferenceQuery,
  selectExternalReferenceQuery,
  selectAllExternalReferences,
  deleteExternalReferenceQuery,
  externalReferencePredicateMap,
} from './sparql-query.js';

const cyioExternalReferenceResolvers = {
  Query: {
    cyioExternalReferences: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllExternalReferences(selectMap.getNode('node'), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: 'Select External Reference List',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer('EXTERNAL-REFERENCE');
        let filterCount;
        let resultCount;
        let limit;
        let offset;
        let limitSize;
        let offsetSize;
        limitSize = limit = args.first === undefined ? response.length : args.first;
        offsetSize = offset = args.offset === undefined ? 0 : args.offset;
        filterCount = 0;
        let externalRefList;
        if (args.orderedBy !== undefined) {
          externalRefList = response.sort(compareValues(args.orderedBy, args.orderMode));
        } else {
          externalRefList = response;
        }

        if (offset > externalRefList.length) return null;

        // for each asset in the result set
        for (const externalRef of externalRefList) {
          // skip down past the offset
          if (offset) {
            offset--;
            continue;
          }

          if (externalRef.id === undefined || externalRef.id == null) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${externalRef.iri} missing field 'id'; skipping`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(externalRef, args.filters, args.filterMode)) {
              continue;
            }
            filterCount++;
          }

          // if haven't reached limit to be returned
          if (limit) {
            const edge = {
              cursor: externalRef.iri,
              node: reducer(externalRef),
            };
            edges.push(edge);
            limit--;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0) return null;
        let hasNextPage = false;
        let hasPreviousPage = false;
        resultCount = externalRefList.length;
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
      // Handle reporting Stardog Error
      if (typeof response === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      } else {
        return null;
      }
    },
    cyioExternalReference: async (_, { id }, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectExternalReferenceQuery(id, selectMap.getNode('cyioExternalReference'));
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

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer('EXTERNAL-REFERENCE');
        return reducer(response[0]);
      }
      // Handle reporting Stardog Error
      if (typeof response === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      } else {
        return null;
      }
    },
  },
  Mutation: {
    createCyioExternalReference: async (_, { input }, { dbName, selectMap, dataSources }) => {
      // TODO: WORKAROUND to remove input fields with null or empty values so creation will work
      for (const [key, value] of Object.entries(input)) {
        if (Array.isArray(input[key]) && input[key].length === 0) {
          delete input[key];
          continue;
        }
        if (value === null || value.length === 0) {
          delete input[key];
        }
      }
      // END WORKAROUND

      const { id, query } = insertExternalReferenceQuery(input);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: query,
        queryId: 'Create External Reference',
      });
      const select = selectExternalReferenceQuery(id, selectMap.getNode('createCyioExternalReference'));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: 'Select External Reference',
        singularizeSchema,
      });
      const reducer = getReducer('EXTERNAL-REFERENCE');
      return reducer(result[0]);
    },
    deleteCyioExternalReference: async (_, { id }, { dbName, dataSources }) => {
      const query = deleteExternalReferenceQuery(id);
      const results = await dataSources.Stardog.delete({
        dbName,
        sparqlQuery: query,
        queryId: 'Delete External Reference',
      });
      if (results !== undefined && 'status' in results) {
        if (results.ok === false || results.status > 299) {
          // Handle reporting Stardog Error
          throw new UserInputError(results.statusText, {
            error_details: results.body.message ? results.body.message : results.body,
            error_code: results.body.code ? results.body.code : 'N/A',
          });
        }
      }
      return id;
    },
    editCyioExternalReference: async (_, { id, input }, { dbName, dataSources, selectMap }) => {
      // make sure there is input data containing what is to be edited
      if (input === undefined || input.length === 0) throw new CyioError(`No input data was supplied`);

      // TODO: WORKAROUND to remove immutable fields
      input = input.filter(
        (element) => element.key !== 'id' && element.key !== 'created' && element.key !== 'modified'
      );

      // check that the object to be edited exists with the predicates - only get the minimum of data
      const editSelect = ['id'];
      for (const editItem of input) {
        editSelect.push(editItem.key);
      }

      const sparqlQuery = selectExternalReferenceQuery(id, editSelect);
      const response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: 'Select ExternalReference',
        singularizeSchema,
      });
      if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);

      // determine operation, if missing
      for (const editItem of input) {
        if (editItem.operation !== undefined) continue;

        // if value if empty then treat as a remove
        if (editItem.value.length === 0 || editItem.value[0].length === 0) {
          editItem.operation = 'remove';
          continue;
        }
        if (!response[0].hasOwnProperty(editItem.key)) {
          editItem.operation = 'add';
        } else {
          editItem.operation = 'replace';
        }
      }

      const query = updateQuery(
        `http://darklight.ai/ns/common#ExternalReference-${id}`,
        'http://darklight.ai/ns/common#ExternalReference',
        input,
        externalReferencePredicateMap
      );
      const results = await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: 'Update External Reference',
      });
      if (results !== undefined && 'status' in results) {
        if (results.ok === false || results.status > 299) {
          // Handle reporting Stardog Error
          throw new UserInputError(results.statusText, {
            error_details: results.body.message ? results.body.message : results.body,
            error_code: results.body.code ? results.body.code : 'N/A',
          });
        }
      }
      const select = selectExternalReferenceQuery(id, selectMap.getNode('editCyioExternalReference'));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: 'Select External Reference',
        singularizeSchema,
      });
      const reducer = getReducer('EXTERNAL-REFERENCE');
      return reducer(result[0]);
    },
  },
};

export default cyioExternalReferenceResolvers;
