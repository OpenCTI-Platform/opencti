import { riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import { compareValues, updateQuery, filterValues } from '../../../utils.js';
import { UserInputError } from "apollo-server-express";
import {
  selectLabelByIriQuery,
  selectExternalReferenceByIriQuery,
  selectNoteByIriQuery,
  getReducer as getGlobalReducer,
} from '../../../global/resolvers/sparql-query.js';
import {
  getReducer,
  insertRiskLogEntryQuery,
  selectRiskLogEntryQuery,
  selectAllRiskLogEntries,
  deleteRiskLogEntryQuery,
  riskLogPredicateMap,
  attachToRiskLogEntryQuery,
  attachToRiskQuery,
  detachFromRiskQuery,
  selectRiskResponseByIriQuery,
  selectOscalTaskByIriQuery,
  insertLogEntryAuthorsQuery,
  deleteLogEntryAuthorByIriQuery,
  selectLogEntryAuthorByIriQuery,
} from './sparql-query.js';

const logEntryResolvers = {
  Query: {
    assessmentLogEntries: async (_, _args, {_dbName, _dataSources, _selectMap}) => { return null },
    assessmentLogEntry: async (_, {_id}, {_dbName, _dataSources, _selectMap}) => { return null },
    riskLogEntries: async (_, args, {dbName, dataSources, selectMap}) => {
      const sparqlQuery = selectAllRiskLogEntries(selectMap.getNode("node"), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Risk Log Entry List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer("RISK-LOG-ENTRY");
        let limit, offset, limitSize, offsetSize;
        limitSize = limit = (args.first === undefined ? response.length : args.first) ;
        offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
        let logEntryList ;
        if (args.orderedBy !== undefined ) {
          logEntryList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          logEntryList = response;
        }

        if (offset > logEntryList.length) return null;

        // for each Log Entry in the result set
        for (let logEntry of logEntryList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (logEntry.id === undefined || logEntry.id == null ) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${logEntry.iri} missing field 'id'; skipping`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(logEntry, args.filters, args.filterMode) ) {
              continue
            }
          }

          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: logEntry.iri,
              node: reducer(logEntry),
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
            hasNextPage: (edges.length < limitSize + 1 ? false : true),
            hasPreviousPage: (offsetSize > 0 ? true : false),
            globalCount: logEntryList.length,
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
    riskLogEntry: async (_, {id}, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectRiskLogEntryQuery(id, selectMap.getNode("riskLogEntry"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Risk LogEntry",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer("RISK-LOG-ENTRY");
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
    },
  },
  Mutation: {
    createAssessmentLogEntry: async ( _, {_input}, {_dbName, _dataSources, _selectMap} ) => {},
    deleteAssessmentLogEntry: async ( _, {_resultId, _id}, {_dbName, _dataSources} ) => {},
    editAssessmentLogEntry: async (_, {_id, _input}, {_dbName, _dataSources, _selectMap}) => {},
    createRiskLogEntry: async ( _, {input}, {dbName, selectMap, dataSources} ) => {
      // Setup to handle embedded objects to be created
      let riskId, responses, authors;
      if (input.logged_by !== undefined) authors = input.logged_by;
      if (input.related_responses !== undefined) responses = input.related_responses;
      if (input.risk_id !== undefined) riskId = input.risk_id;

      // create the Risk Log Entry
      const {iri, id, query} = insertRiskLogEntryQuery(input);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: query,
        queryId: "Create Risk Log Entry"
      });

      // add the Risk Log Entry to the Risk, if specified
      if (riskId !== undefined && riskId !== null) {
        const attachQuery = attachToRiskQuery( riskId, 'risk_log', iri );
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: attachQuery,
            queryId: "Add Risk Log Entry to Risk"
          });
        } catch (e) {
          console.log(e)
          throw e
        }  
      }

      // create any authors supplied and attach them to the log entry 
      if (authors !== undefined && authors !== null ) {
        // create the Log Entry Author
        const {authorIris, query} = insertLogEntryAuthorsQuery( authors );
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: "Create Authors of Log Entry"
        });
        // attach the Author to the Party
        const authorAttachQuery = attachToRiskLogEntryQuery(id, 'logged_by', authorIris);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: authorAttachQuery,
          queryId: "Attach Authors to Log Entry"
        });

      }

      // Create references to the Risk Responses
      if (responses !== undefined && responses !== null ) {
        const responseIris = []
        for (let responseId of responses) responseIris.push(`<http://csrc.nist.gov/ns/oscal/assessment/common#RiskResponse-${responseId}>`);

        // attach the reference to the Risk Log Entry
        const responseAttachQuery = attachToRiskLogEntryQuery(id, 'related_responses', responseIris);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: responseAttachQuery,
          queryId: "Attach reference to a related Risk Responses to this Risk Log Entry"
        });
      }
    
      const select = selectRiskLogEntryQuery(id, selectMap.getNode("createRiskLogEntry"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: "Select Risk Log Entry",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      const reducer = getReducer("RISK-LOG-ENTRY");
      return reducer(response[0]);
    },
    deleteRiskLogEntry: async ( _, {riskId, id}, {dbName, dataSources} ) => {
      // check that the risk log entry exists
      const sparqlQuery = selectRiskLogEntryQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Risk Log Entry",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      const reducer = getReducer("RISK-LOG-ENTRY");
      const logEntry = reducer(response[0]);

      // delete any attached authors of the Log Entry
      if (logEntry.hasOwnProperty('logged_by_iri')) {
        for (const authorIri of logEntry.logged_by_iri) {
          const authorQuery = deleteLogEntryAuthorByIriQuery(authorIri);
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: authorQuery,
            queryId: "Delete Authors from this Log Entry"
          });
        }
      }

      // There is no need to detach responses as they are not 'owned' by the log entry

      // detach the Risk Log Entry from the Risk
      if (riskId !== undefined && riskId !== null) {
        const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#RiskLogEntry-${id}`
        const detachQuery = detachFromRiskQuery( riskId, 'risk_log', iri );
        try {
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: detachQuery,
            queryId: "Detach Risk Log Entry from Risk"
          });
        } catch (e) {
          console.log(e)
          throw e
        }
      }
            
      // Delete the risk log entry
      const query = deleteRiskLogEntryQuery(id);
      try {
        await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: "Delete Risk Log Entry"
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      return id;
    },
    editRiskLogEntry: async (_, {id, input}, {dbName, dataSources, selectMap}) => {
      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/assessment/common#RiskLogEntry-${id}`,
        "http://csrc.nist.gov/ns/oscal/assessment/common#RiskLogEntry",
        input,
        riskLogPredicateMap
      )
      await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update Risk Log Entry"
      });
      const select = selectRiskLogEntryQuery(id, selectMap.getNode("editRiskLogEntry"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select Risk Log Entry",
        singularizeSchema
      });
      const reducer = getReducer("RISK-LOG-ENTRY");
      return reducer(result[0]);

    },
},
  AssessmentLogEntry: {
    labels: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.labels_iri === undefined) return [];
      let iriArray = parent.labels_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("LABEL");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Label')) {
            continue;
          }
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
          if (response === undefined) return [];
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
    links: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.ext_ref_iri === undefined) return [];
      let iriArray = parent.ext_ref_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("EXTERNAL-REFERENCE");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('ExternalReference')) {
            continue;
          }
          const sparqlQuery = selectExternalReferenceByIriQuery(iri, selectMap.getNode("links"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Link",
              singularizeSchema
            });
          } catch (e) {
            console.log(e)
            throw e
          }
          if (response === undefined) return [];
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
    remarks: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.notes_iri === undefined) return [];
      let iriArray = parent.notes_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("NOTE");
        const sparqlQuery = selectNoteQuery(id, selectMap.getNode("remarks"));
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Note')) {
            continue;
          }
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
          if (response === undefined) return [];
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
    related_tasks: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.related_tasks_iri === undefined) return [];
      let iriArray = parent.related_tasks_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer("TASK");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Task')) {
            continue;
          }
          const sparqlQuery = selectOscalTaskByIriQuery(iri, selectMap.getNode("related_tasks"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Task",
              singularizeSchema
            });
          } catch (e) {
            console.log(e)
            throw e
          }
          if (response === undefined) return [];
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
  },
  RiskLogEntry: {
    labels: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.labels_iri === undefined) return [];
      let iriArray = parent.labels_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("LABEL");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Label')) {
            continue;
          }
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
          if (response === undefined) return [];
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
    links: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.ext_ref_iri === undefined) return [];
      let iriArray = parent.ext_ref_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("EXTERNAL-REFERENCE");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('ExternalReference')) {
            continue;
          }
          const sparqlQuery = selectExternalReferenceByIriQuery(iri, selectMap.getNode("links"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Link",
              singularizeSchema
            });
          } catch (e) {
            console.log(e)
            throw e
          }
          if (response === undefined) return [];
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
    remarks: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.notes_iri === undefined) return [];
      let iriArray = parent.notes_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("NOTE");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Note')) {
            continue;
          }
          const sparqlQuery = selectNoteByIriQuery(iri, selectMap.getNode("remarks"));
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
          if (response === undefined) return [];
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
    logged_by: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.logged_by_iri === undefined) return [];
      let iriArray = parent.logged_by_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer("LOG-ENTRY-AUTHOR");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('LogEntryAuthor')) {
            continue;
          }
          const sparqlQuery = selectLogEntryAuthorByIriQuery(iri, selectMap.getNode("logged_by"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Log Entry Author",
              singularizeSchema
            });
          } catch (e) {
            console.log(e)
            throw e
          }
          if (response === undefined) return [];
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
    related_responses: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.related_responses_iri === undefined) return [];
      let iriArray = parent.related_responses_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer("RISK-RESPONSE");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('RiskResponse')) {
            continue;
          }
          const sparqlQuery = selectRiskResponseByIriQuery(iri, selectMap.getNode("related_responses"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select RiskResponse",
              singularizeSchema
            });
          } catch (e) {
            console.log(e)
            throw e
          }
          if (response === undefined) return [];
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
  },
}

export default logEntryResolvers;