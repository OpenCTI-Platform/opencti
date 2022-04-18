import { assetSingularizeSchema as singularizeSchema } from '../../assets/asset-mappings.js';
import {compareValues, updateQuery, filterValues} from '../../utils.js';
import {UserInputError} from "apollo-server-express";
import {
  getReducer, 
  insertExternalReferenceQuery,
  selectExternalReferenceQuery,
  selectAllExternalReferences,
  deleteExternalReferenceQuery,
  externalReferencePredicateMap
} from './sparql-query.js';


const cyioExternalReferenceResolvers = {
  Query: {
    cyioExternalReferences: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllExternalReferences(selectMap.getNode("node"), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select External Reference List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer("EXTERNAL-REFERENCE");
        let limit = (args.limit === undefined ? response.length : args.limit) ;
        let offset = (args.offset === undefined ? 0 : args.offset) ;
        let externalRefList ;
        if (args.orderedBy !== undefined ) {
          externalRefList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          externalRefList = response;
        }

        if (offset > externalRefList.length) return null;

        // for each asset in the result set
        for (let externalRef of externalRefList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (externalRef.id === undefined || externalRef.id == null ) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${externalRef.iri} missing field 'id'; skipping`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(externalRef, args.filters, args.filterMode) ) {
              continue
            }
          }

          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: externalRef.iri,
              node: reducer(externalRef),
            }
            edges.push(edge)
            limit--;
          }
        }
        if (edges.length === 0 ) return null;
        return {
          pageInfo: {
            startCursor: edges[0].cursor,
            endCursor: edges[edges.length-1].cursor,
            hasNextPage: (args.limit < externalRefList.length ? true : false),
            hasPreviousPage: (args.offset > 0 ? true : false),
            globalCount: externalRefList.length,
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
    cyioExternalReference: async (_, {id}, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectExternalReferenceQuery(id, selectMap.getNode("cyioExternalReference"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select External Reference",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer("EXTERNAL-REFERENCE");
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
    createCyioExternalReference: async ( _, {input}, {dbName, selectMap, dataSources} ) => {
      const {id, query} = insertExternalReferenceQuery(input);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: query,
        queryId: "Create External Reference"
      });
      const select = selectExternalReferenceQuery(id, selectMap.getNode("createCyioExternalReference"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select External Reference",
        singularizeSchema
      });
      const reducer = getReducer("EXTERNAL-REFERENCE");
      return reducer(result[0]);
    },
    deleteCyioExternalReference: async ( _, {id}, {dbName, dataSources} ) => {
      const query = deleteExternalReferenceQuery(id);
      await dataSources.Stardog.delete({
        dbName,
        sparqlQuery: query,
        queryId: "Delete External Reference"
      });
      return id;
    },
    editCyioExternalReference: async (_, {id, input}, {dbName, dataSources, selectMap}) => {
      const query = updateQuery(
        `http://darklight.ai/ns/common#ExternalReference-${id}`,
        "http://darklight.ai/ns/common#ExternalReference",
        input,
        externalReferencePredicateMap
      )
      await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update External Reference"
      });
      const select = selectExternalReferenceQuery(id, selectMap.getNode("editCyioExternalReference"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select External Reference",
        singularizeSchema
      });
      const reducer = getReducer("EXTERNAL-REFERENCE");
      return reducer(result[0]);
    },
  },
};

export default cyioExternalReferenceResolvers;
