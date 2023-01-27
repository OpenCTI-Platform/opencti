import { UserInputError } from 'apollo-server-express';
import { riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import { compareValues, updateQuery, filterValues, CyioError } from '../../../utils.js';
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
  selectRiskQuery,
  attachToRiskQuery,
  detachFromRiskQuery,
  selectRiskResponseQuery,
  selectRiskResponseByIriQuery,
  selectOscalTaskByIriQuery,
  insertLogEntryAuthorsQuery,
  deleteLogEntryAuthorByIriQuery,
  selectLogEntryAuthorQuery,
  selectLogEntryAuthorByIriQuery,
  selectAllLogEntryAuthors,
} from './sparql-query.js';
import {
  selectPartyQuery,
  selectPartyByIriQuery,
  getReducer as getCommonReducer,
} from '../../oscal-common/resolvers/sparql-query.js';

const logEntryResolvers = {
  Query: {
    assessmentLogEntries: async (_, _args, { _dbName, _dataSources, _selectMap }) => {
      return null;
    },
    assessmentLogEntry: async (_, { _id }, { _dbName, _dataSources, _selectMap }) => {
      return null;
    },
    riskLogEntries: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllRiskLogEntries(selectMap.getNode('node'), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: 'Select Risk Log Entry List',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer('RISK-LOG-ENTRY');
        let filterCount;
        let resultCount;
        let limit;
        let offset;
        let limitSize;
        let offsetSize;
        limitSize = limit = args.first === undefined ? response.length : args.first;
        offsetSize = offset = args.offset === undefined ? 0 : args.offset;
        filterCount = 0;
        let logEntryList;
        if (args.orderedBy !== undefined) {
          logEntryList = response.sort(compareValues(args.orderedBy, args.orderMode));
        } else {
          logEntryList = response;
        }

        if (offset > logEntryList.length) return null;

        // for each Log Entry in the result set
        for (const logEntry of logEntryList) {
          if (logEntry.id === undefined || logEntry.id == null) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${logEntry.iri} missing field 'id'; skipping`);
            continue;
          }

          // skip down past the offset
          if (offset) {
            offset--;
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(logEntry, args.filters, args.filterMode)) {
              continue;
            }
            filterCount++;
          }

          // TODO: WORKAROUND data issues
          if (logEntry.hasOwnProperty('entry_type')) {
            for (const entry in logEntry.entry_type) {
              logEntry.entry_type[entry] = logEntry.entry_type[entry].replace(/_/g, '-');
            }
          }
          // END WORKAROUND

          // if haven't reached limit to be returned
          if (limit) {
            const edge = {
              cursor: logEntry.iri,
              node: reducer(logEntry),
            };
            edges.push(edge);
            limit--;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0) return null;
        let hasNextPage = false;
        let hasPreviousPage = false;
        resultCount = logEntryList.length;
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
    riskLogEntry: async (_, { id }, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectRiskLogEntryQuery(id, selectMap.getNode('riskLogEntry'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select Risk LogEntry',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer('RISK-LOG-ENTRY');
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
    logEntryAuthors: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllLogEntryAuthors(selectMap.getNode('node'), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: 'Select LogEntry Author List',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer('LOG-ENTRY-AUTHOR');
        let filterCount;
        let resultCount;
        let limit;
        let offset;
        let limitSize;
        let offsetSize;
        limitSize = limit = args.first === undefined ? response.length : args.first;
        offsetSize = offset = args.offset === undefined ? 0 : args.offset;
        filterCount = 0;
        let authorList;
        if (args.orderedBy !== undefined) {
          authorList = response.sort(compareValues(args.orderedBy, args.orderMode));
        } else {
          authorList = response;
        }

        if (offset > authorList.length) return null;

        // for each Log Entry in the result set
        for (const author of authorList) {
          if (author.id === undefined || author.id == null) {
            console.log(
              `[CYIO] (${dbName}) CONSTRAINT-VIOLATION: (${dbName}) ${author.iri} missing field 'id'; skipping`
            );
            continue;
          }
          if (author.party === undefined || author.party == null) {
            console.log(
              `[CYIO] (${dbName}) CONSTRAINT-VIOLATION: (${dbName}) ${author.iri} missing field 'party'; skipping`
            );
            continue;
          }

          let found = false;
          for (const party of author.party) {
            if (party.includes('Party-undefined')) {
              console.error(
                `[CYIO] INVALID-IRI: (${dbName}) ${author.iri} 'party' contains an IRI ${party} which is invalid; skipping`
              );
              found = true;
              break;
            }
          }
          if (found) continue;

          // skip down past the offset
          if (offset) {
            offset--;
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(author, args.filters, args.filterMode)) {
              continue;
            }
            filterCount++;
          }

          // if haven't reached limit to be returned
          if (limit) {
            const edge = {
              cursor: author.iri,
              node: reducer(author),
            };
            edges.push(edge);
            limit--;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0) return null;
        let hasNextPage = false;
        let hasPreviousPage = false;
        resultCount = authorList.length;
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
    logEntryAuthor: async (_, { id }, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectLogEntryAuthorQuery(id, selectMap.getNode('logEntryAuthor'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select LogEntry Author',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer('LOG-ENTRY-AUTHOR');
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
    createAssessmentLogEntry: async (_, { _input }, { _dbName, _dataSources, _selectMap }) => {},
    deleteAssessmentLogEntry: async (_, { _resultId, _id }, { _dbName, _dataSources }) => {},
    editAssessmentLogEntry: async (_, { _id, _input }, { _dbName, _dataSources, _selectMap }) => {},
    createRiskLogEntry: async (_, { input }, { dbName, selectMap, dataSources }) => {
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

      // Setup to handle embedded objects to be created
      let riskId;
      let responses;
      let authors;
      if (input.risk_id !== undefined) {
        riskId = input.risk_id;

        // check that the Risk exists
        const sparqlQuery = selectRiskQuery(riskId, ['id']);
        let response;
        try {
          response = await dataSources.Stardog.queryById({
            dbName,
            sparqlQuery,
            queryId: 'Checking existence of Risk object',
            singularizeSchema,
          });
        } catch (e) {
          console.log(e);
          throw e;
        }
        if (response.length === 0) throw new CyioError(`Risk does not exist with ID ${riskId}`);
      }
      if (input.logged_by !== undefined) {
        authors = input.logged_by;
        for (const author of authors) {
          // check that the Party exists
          const sparqlQuery = selectPartyQuery(author.party, ['id']);
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Checking existence of Party object',
              singularizeSchema,
            });
          } catch (e) {
            console.log(e);
            throw e;
          }

          if (response.length === 0) throw new CyioError(`Party does not exist with ID ${author.party}`);
        }
      }
      if (input.related_responses !== undefined) {
        responses = input.related_responses;
        for (const responseId of responses) {
          // check that the Risk exists
          const sparqlQuery = selectRiskResponseQuery(responseId, ['id']);
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Checking existence of Risk Response object',
              singularizeSchema,
            });
          } catch (e) {
            console.log(e);
            throw e;
          }

          if (response.length === 0) throw new CyioError(`Risk Response does not exist with ID ${responseId}`);
        }
      }

      // create the Risk Log Entry
      const { iri, id, query } = insertRiskLogEntryQuery(input);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: query,
        queryId: 'Create Risk Log Entry',
      });

      // add the Risk Log Entry to the Risk, if specified
      if (riskId !== undefined && riskId !== null) {
        const attachQuery = attachToRiskQuery(riskId, 'risk_log', iri);
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: attachQuery,
            queryId: 'Add Risk Log Entry to Risk',
          });
        } catch (e) {
          console.log(e);
          throw e;
        }
      }

      // create any authors supplied and attach them to the log entry
      if (authors !== undefined && authors !== null) {
        // create the Log Entry Author
        let result;
        const { authorIris, query } = insertLogEntryAuthorsQuery(authors);
        result = await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: 'Create Authors of Log Entry',
        });
        // attach the Author to the Party
        const authorAttachQuery = attachToRiskLogEntryQuery(id, 'logged_by', authorIris);
        result = await dataSources.Stardog.create({
          dbName,
          sparqlQuery: authorAttachQuery,
          queryId: 'Attach Authors to Log Entry',
        });
      }

      // Create references to the Risk Responses
      if (responses !== undefined && responses !== null) {
        const responseIris = [];
        for (const responseId of responses)
          responseIris.push(`<http://csrc.nist.gov/ns/oscal/assessment/common#RiskResponse-${responseId}>`);

        // attach the reference to the Risk Log Entry
        const responseAttachQuery = attachToRiskLogEntryQuery(id, 'related_responses', responseIris);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: responseAttachQuery,
          queryId: 'Attach reference to a related Risk Responses to this Risk Log Entry',
        });
      }

      const select = selectRiskLogEntryQuery(id, selectMap.getNode('createRiskLogEntry'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: 'Select Risk Log Entry',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      const reducer = getReducer('RISK-LOG-ENTRY');
      return reducer(response[0]);
    },
    deleteRiskLogEntry: async (_, { riskId, id }, { dbName, dataSources }) => {
      // check that the risk log entry exists
      const sparqlQuery = selectRiskLogEntryQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select Risk Log Entry',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);
      const reducer = getReducer('RISK-LOG-ENTRY');
      const logEntry = reducer(response[0]);

      // delete any attached authors of the Log Entry
      if (logEntry.hasOwnProperty('logged_by_iri')) {
        for (const authorIri of logEntry.logged_by_iri) {
          const authorQuery = deleteLogEntryAuthorByIriQuery(authorIri);
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: authorQuery,
            queryId: 'Delete Authors from this Log Entry',
          });
        }
      }

      // There is no need to detach responses as they are not 'owned' by the log entry

      // detach the Risk Log Entry from the Risk
      if (riskId !== undefined && riskId !== null) {
        const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#RiskLogEntry-${id}`;
        const detachQuery = detachFromRiskQuery(riskId, 'risk_log', iri);
        try {
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: detachQuery,
            queryId: 'Detach Risk Log Entry from Risk',
          });
        } catch (e) {
          console.log(e);
          throw e;
        }
      }

      // Delete the risk log entry
      const query = deleteRiskLogEntryQuery(id);
      try {
        await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: 'Delete Risk Log Entry',
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      return id;
    },
    editRiskLogEntry: async (_, { id, input }, { dbName, dataSources, selectMap }) => {
      // make sure there is input data containing what is to be edited
      if (input === undefined || input.length === 0) throw new CyioError(`No input data was supplied`);

      // TODO: WORKAROUND to remove immutable fields
      input = input.filter(
        (element) => element.key !== 'id' && element.key !== 'created' && element.key !== 'modified'
      );

      // check that the object to be edited exists with the predicates - only get the minimum of data
      const editSelect = ['id', 'created', 'modified'];
      for (const editItem of input) {
        editSelect.push(editItem.key);
      }

      const sparqlQuery = selectRiskLogEntryQuery(id, editSelect);
      const response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: 'Select Risk Log Entry',
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

      // Push an edit to update the modified time of the object
      const timestamp = new Date().toISOString();
      if (!response[0].hasOwnProperty('created')) {
        const update = { key: 'created', value: [`${timestamp}`], operation: 'add' };
        input.push(update);
      }
      let operation = 'replace';
      if (!response[0].hasOwnProperty('modified')) operation = 'add';
      const update = { key: 'modified', value: [`${timestamp}`], operation: `${operation}` };
      input.push(update);

      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/assessment/common#RiskLogEntry-${id}`,
        'http://csrc.nist.gov/ns/oscal/assessment/common#RiskLogEntry',
        input,
        riskLogPredicateMap
      );
      if (query !== null) {
        let response;
        try {
          response = await dataSources.Stardog.edit({
            dbName,
            sparqlQuery: query,
            queryId: 'Update Risk Log Entry',
          });
        } catch (e) {
          console.log(e);
          throw e;
        }

        if (response !== undefined && 'status' in response) {
          if (response.ok === false || response.status > 299) {
            // Handle reporting Stardog Error
            throw new UserInputError(response.statusText, {
              error_details: response.body.message ? response.body.message : response.body,
              error_code: response.body.code ? response.body.code : 'N/A',
            });
          }
        }
      }

      const select = selectRiskLogEntryQuery(id, selectMap.getNode('editRiskLogEntry'));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: 'Select Risk Log Entry',
        singularizeSchema,
      });
      const reducer = getReducer('RISK-LOG-ENTRY');
      return reducer(result[0]);
    },
  },
  AssessmentLogEntry: {
    labels: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.labels_iri === undefined) return [];
      const iriArray = parent.labels_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer('LABEL');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Label')) {
            continue;
          }
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
          if (iri === undefined || !iri.includes('ExternalReference')) {
            continue;
          }
          const sparqlQuery = selectExternalReferenceByIriQuery(iri, selectMap.getNode('links'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Link',
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
        const sparqlQuery = selectNoteQuery(id, selectMap.getNode('remarks'));
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Note')) {
            continue;
          }
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
    related_tasks: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.related_tasks_iri === undefined) return [];
      const iriArray = parent.related_tasks_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer('TASK');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Task')) {
            continue;
          }
          const sparqlQuery = selectOscalTaskByIriQuery(iri, selectMap.getNode('related_tasks'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Task',
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
  },
  RiskLogEntry: {
    labels: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.labels_iri === undefined) return [];
      const iriArray = parent.labels_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer('LABEL');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Label')) {
            continue;
          }
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
          if (iri === undefined || !iri.includes('ExternalReference')) {
            continue;
          }
          const sparqlQuery = selectExternalReferenceByIriQuery(iri, selectMap.getNode('links'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Link',
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
          if (iri === undefined || !iri.includes('Note')) {
            continue;
          }
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
    logged_by: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.logged_by_iri === undefined) return [];
      const iriArray = parent.logged_by_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer('LOG-ENTRY-AUTHOR');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('LogEntryAuthor')) {
            continue;
          }
          const sparqlQuery = selectLogEntryAuthorByIriQuery(iri, selectMap.getNode('logged_by'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Log Entry Author',
              singularizeSchema,
            });
          } catch (e) {
            console.log(e);
            throw e;
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            // Return a null logEntryAuthor if it has a reference to the party that is bad or missing
            if (response[0].hasOwnProperty('party')) {
              let parties = [];
              for (const party of response[0].party) {
                if (party.includes('Party-undefined')) {
                  console.error(
                    `[CYIO] INVALID-IRI: (${dbName}) ${response[0].iri} 'party' contains an IRI ${party} which is invalid; skipping`
                  );
                  continue;
                }
                parties.push(party);
              }
              if (parties.length === 0) parties = null;
              response[0].party = parties;
            }
            if (response[0].party !== null) results.push(reducer(response[0]));
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
    related_responses: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.related_responses_iri === undefined) return [];
      const iriArray = parent.related_responses_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer('RISK-RESPONSE');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('RiskResponse')) {
            continue;
          }
          const sparqlQuery = selectRiskResponseByIriQuery(iri, selectMap.getNode('related_responses'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select RiskResponse',
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
  },
  LogEntryAuthor: {
    party: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.party_iri === undefined) return null;
      const reducer = getCommonReducer('PARTY');
      const iri = parent.party_iri[0];
      const sparqlQuery = selectPartyByIriQuery(iri, selectMap.getNode('party'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select Party',
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
      if (Array.isArray(response) && response.length > 0) {
        return reducer(response[0]);
      }

      return null;
    },
    role: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.role_iri === undefined) return null;
      const reducer = getCommonReducer('PARTY');
      const iri = parent.role_iri[0];
      const sparqlQuery = selectPartyByIriQuery(iri, selectMap.getNode('party'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select Party',
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
        return reducer(response[0]);
      }

      return null;
    },
  },
};

export default logEntryResolvers;
