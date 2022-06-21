import { assetSingularizeSchema as singularizeSchema } from '../../assets/asset-mappings.js';
import {compareValues, updateQuery, filterValues} from '../../utils.js';
import {UserInputError} from "apollo-server-express";
import {
  getReducer, 
  insertNoteQuery,
  selectNoteQuery,
  selectAllNotes,
  deleteNoteQuery,
  notePredicateMap
} from './sparql-query.js';


const cyioNoteResolvers = {
  Query: {
    cyioNotes: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllNotes(selectMap.getNode("node"), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Note List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer("NOTE");
        let filterCount, resultCount, limit, offset, limitSize, offsetSize;
        limitSize = limit = (args.first === undefined ? response.length : args.first) ;
        offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
        filterCount = 0;
        let noteList ;
        if (args.orderedBy !== undefined ) {
          noteList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          noteList = response;
        }

        if (offset > noteList.length) return null;

        // for each asset in the result set
        for (let note of noteList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (note.id === undefined || note.id == null ) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${note.iri} missing field 'id'; skipping`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(note, args.filters, args.filterMode) ) {
              continue
            }
            filterCount++;
          }

          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: note.iri,
              node: reducer(note),
            }
            edges.push(edge)
            limit--;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0 ) return null;
        let hasNextPage = false, hasPreviousPage = false;
        resultCount = noteList.length;
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
    cyioNote: async (_, {id}, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectNoteQuery(id, selectMap.getNode("cyioNote"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Note",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer("NOTE");
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
    createCyioNote: async ( _, {input}, {dbName, selectMap, dataSources} ) => {
      const {id, query} = insertNoteQuery(input);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: query,
        queryId: "Create Note"
      });
      const select = selectNoteQuery(id, selectMap.getNode("createCyioNote"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select Note",
        singularizeSchema
      });
      const reducer = getReducer("NOTE");
      return reducer(result[0]);
    },
    deleteCyioNote: async ( _, {id}, {dbName, dataSources} ) => {
      const query = deleteNoteQuery(id);
      let results = await dataSources.Stardog.delete({
        dbName,
        sparqlQuery: query,
        queryId: "Delete note"
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
    editCyioNote: async (_, {id, input}, {dbName, dataSources, selectMap}) => {
      // check that the object to be edited exists with the predicates - only get the minimum of data
      let editSelect = ['id'];
      for (let editItem of input) {
        editSelect.push(editItem.key);
      }
      const sparqlQuery = selectNoteQuery(id, editSelect );
      let response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select Note",
        singularizeSchema
      })
      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

      // TODO: WORKAROUND to handle UI where it DOES NOT provide an explicit operation
      for (let editItem of input) {
        if (!response[0].hasOwnProperty(editItem.key)) editItem.operation = 'add';
      }
      // END WORKAROUND

      const query = updateQuery(
        `http://darklight.ai/ns/common#Note-${id}`,
        "http://darklight.ai/ns/common#Note",
        input,
        notePredicateMap
      );
      let results = await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update Note"
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

      const select = selectNoteQuery(id, selectMap.getNode("editCyioNote"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select Note",
        singularizeSchema
      });
      const reducer = getReducer("NOTE");
      return reducer(result[0]);
    },
  },
  CyioNote: {
    labels: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.labels_iri === undefined) return [];
      let iriArray = parent.labels_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("LABEL");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Label')) continue;
          const sparqlQuery = selectLabelByIriQuery(iri, selectMap.getNode("labels"));
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
          if (response === undefined || (Array.isArray(response) && response.length === 0)) {
            console.error(`[CYIO] NON-EXISTENT: (${dbName}) '${iri}'; skipping entity`);              
            continue;
          }
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]))
          }
          else {
            // Handle reporting Stardog Error
            if (typeof (response) === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: (response.body.message ? response.body.message : response.body),
                error_code: (response.body.code ? response.body.code : 'N/A')
              });
            }
          }  
        }
        return results;
      } else {
        return [];
      }
    },
  }
};

export default cyioNoteResolvers;
