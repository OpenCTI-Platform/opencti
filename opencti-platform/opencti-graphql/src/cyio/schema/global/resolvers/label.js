import { assetSingularizeSchema as singularizeSchema } from '../../assets/asset-mappings.js';
import {compareValues, updateQuery, filterValues} from '../../utils.js';
import {UserInputError} from "apollo-server-express";
import {
  getReducer, 
  insertLabelQuery,
  selectLabelQuery,
  selectAllLabels,
  deleteLabelQuery,
  labelPredicateMap
} from './sparql-query.js';


const cyioLabelResolvers = {
  Query: {
    cyioLabels: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllLabels(selectMap.getNode("node"), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Label List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer("LABEL");
        let filterCount, resultCount, limit, offset, limitSize, offsetSize;
        limitSize = limit = (args.first === undefined ? response.length : args.first) ;
        offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
        filterCount = 0;
        let labelList ;
        if (args.orderedBy !== undefined ) {
          labelList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          labelList = response;
        }

        if (offset > labelList.length) return null;

        // for each asset in the result set
        for (let label of labelList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (label.id === undefined || label.id == null ) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${label.iri} missing field 'id'; skipping`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(label, args.filters, args.filterMode) ) {
              continue
            }
            filterCount++;
          }

          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: label.iri,
              node: reducer(label),
            }
            edges.push(edge)
            limit--;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0 ) return null;
        let hasNextPage = false, hasPreviousPage = false;
        resultCount = labelList.length;
        if (edges.length < resultCount) {
          if (edges.length === limitSize && filterCount <= limitSize ) {
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
            endCursor: edges[edges.length-1].cursor,
            hasNextPage: (hasNextPage ),
            hasPreviousPage: (hasPreviousPage),
            globalCount: resultCount,
          },
          edges: edges,
        }
      } else {
        // Handle reporting Stardog Error
        if (typeof (response) === 'object' && 'body' in response) {
          throw new UserInputError(response.statusText, {
            error_details: (response.body.message ? response.body.message : response.body),
            error_code: (response.body.code ? response.body.code : 'N/A')
          });
        } else {
          return null;
        }
      }
    },
    cyioLabel: async (_, {id}, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectLabelQuery(id, selectMap.getNode("cyioLabel"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Label",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer("LABEL");
        return reducer(response[0]);  
      } else {
        // Handle reporting Stardog Error
        if (typeof (response) === 'object' && 'body' in response) {
          throw new UserInputError(response.statusText, {
            error_details: (response.body.message ? response.body.message : response.body),
            error_code: (response.body.code ? response.body.code : 'N/A')
          });
        } else {
          return null;
        }
      }
    }
  },
  Mutation: {
    createCyioLabel: async ( _, {input}, {dbName, selectMap, dataSources} ) => {
      const {id, query} = insertLabelQuery(input);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: query,
        queryId: "Create Label"
      });
      const select = selectLabelQuery(id, selectMap.getNode("createCyioLabel"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select Label",
        singularizeSchema
      });
      const reducer = getReducer("LABEL");
      return reducer(result[0]);
    },
    deleteCyioLabel: async ( _, {id}, {dbName, dataSources} ) => {
      const query = deleteLabelQuery(id);
      let results = await dataSources.Stardog.delete({
        dbName,
        sparqlQuery: query,
        queryId: "Delete Label"
      });
      if (results !== undefined && 'status' in results) {
        if (results.ok === false || results.status > 299) {
          // Handle reporting Stardog Error
          throw new UserInputError(results.statusText, {
            error_details: (results.body.message ? results.body.message : results.body),
            error_code: (results.body.code ? results.body.code : 'N/A')
          });
        }
      }
      return id;
    },
    editCyioLabel: async (_, {id, input}, {dbName, dataSources, selectMap}) => {
      // check that the object to be edited exists with the predicates - only get the minimum of data
      let editSelect = ['id'];
      for (let editItem of input) {
        editSelect.push(editItem.key);
      }
      const sparqlQuery = selectLabelQuery(id, editSelect );
      let response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select Label",
        singularizeSchema
      })
      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

      // TODO: WORKAROUND to handle UI where it DOES NOT provide an explicit operation
      for (let editItem of input) {
        if (!response[0].hasOwnProperty(editItem.key)) editItem.operation = 'add';
      }
      // END WORKAROUND

      const query = updateQuery(
        `http://darklight.ai/ns/common#Label-${id}`,
        "http://darklight.ai/ns/common#Label",
        input,
        labelPredicateMap
      )
      let results = await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update Label"
      });
      if (results !== undefined && 'status' in results) {
        if (results.ok === false || results.status > 299) {
          // Handle reporting Stardog Error
          throw new UserInputError(results.statusText, {
            error_details: (results.body.message ? results.body.message : results.body),
            error_code: (results.body.code ? results.body.code : 'N/A')
          });
        }
      }

      const select = selectLabelQuery(id, selectMap.getNode("editCyioLabel"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select Label",
        singularizeSchema
      });
      const reducer = getReducer("LABEL");
      return reducer(result[0]);
    },
  },
};

export default cyioLabelResolvers;
