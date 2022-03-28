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
      const sparqlQuery = selectAllLabels(selectMap.getNode("node"));
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

      if (response === undefined) return[];
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer("LABEL");
        let limit = (args.limit === undefined ? response.length : args.limit) ;
        let offset = (args.offset === undefined ? 0 : args.offset) ;
        let labelList ;
        if (args.orderedBy !== undefined ) {
          labelList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          labelList = response;
        }

        if (offset > labelList.length) return

        // for each asset in the result set
        for (let label of labelList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (label.id === undefined || label.id == null ) {
            console.log(`[DATA-ERROR] object ${label.iri} is missing required properties; skipping object.`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(label, args.filters, args.filterMode) ) {
              continue
            }
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
        if (edges.length === 0 ) return null;
        return {
          pageInfo: {
            startCursor: edges[0].cursor,
            endCursor: edges[edges.length-1].cursor,
            hasNextPage: (args.limit > labelList.length),
            hasPreviousPage: (args.offset > 0),
            globalCount: labelList.length,
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
          return ;
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
      await dataSources.Stardog.delete({
        dbName,
        sparqlQuery: query,
        queryId: "Delete Label"
      });
      return id;
    },
    editCyioLabel: async (_, {id, input}, {dbName, dataSources, selectMap}) => {
      const query = updateQuery(
        `http://darklight.ai/ns/common#Label-${id}`,
        "http://darklight.ai/ns/common#Label",
        input,
        labelPredicateMap
      )
      await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update Label"
      });
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
