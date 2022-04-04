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
  insertEvidenceQuery,
  selectEvidenceQuery,
  selectAllEvidence,
  deleteEvidenceQuery,
  evidencePredicateMap,
} from './sparql-query.js';

const evidenceResolvers = {
  Query: {
    evidenceList: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllEvidence(selectMap.getNode("node"), args.filters);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Evidence List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer("EVIDENCE");
        let limit = (args.first === undefined ? response.length : args.first) ;
        let offset = (args.offset === undefined ? 0 : args.offset) ;
        let evidenceList ;
        if (args.orderedBy !== undefined ) {
          evidenceList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          evidenceList = response;
        }

        if (offset > evidenceList.length) return null;

        // for each Risk in the result set
        for (let evidence of evidenceList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (evidence.id === undefined || evidence.id == null ) {
            console.log(`[DATA-ERROR] object ${evidence.iri} is missing required properties; skipping object.`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(evidence, args.filters, args.filterMode) ) {
              continue
            }
          }

          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: evidence.iri,
              node: reducer(evidence),
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
            hasNextPage: (args.first > evidenceList.length),
            hasPreviousPage: (args.offset > 0),
            globalCount: evidenceList.length,
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
    evidence: async (_, {id}, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectEvidenceQuery(id, selectMap.getNode("evidence"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Evidence",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer("EVIDENCE");
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
    createEvidence: async ( _, {input}, {dbName, selectMap, dataSources} ) => {
      // Setup to handle embedded objects to be created
      let observationId;
      if (input.observation_id !== undefined) observationId = input.observation_id;

      // create the Evidence
      const {iri, id, query} = insertEvidenceQuery(input);
      try {
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: "Create Evidence"
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      // add the Evidence to the Observation
      if (observationId !== undefined && observationId !== null) {
        const attachQuery = attachToObservationQuery( observationId, 'relevant_evidence', iri );
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: attachQuery,
            queryId: "Add Evidence to Observation"
          });
        } catch (e) {
          console.log(e)
          throw e
        }  
      }

      // retrieve information about the newly created Evidence to return to the user
      const select = selectEvidenceQuery(id, selectMap.getNode("createEvidence"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: "Select Evidence",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
    const reducer = getReducer("EVIDENCE");
    return reducer(response[0]);
    },
    deleteEvidence: async ( _, {observationId, id}, {dbName, dataSources} ) => {
      // check that the Evidence exists
      const sparqlQuery = selectEvidenceQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Evidence",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      let reducer = getReducer("EVIDENCE");
      const evidence = (reducer(response[0]));

      // detach the Evidence from the Observation
      if (observationId !== undefined && observationId !== null) {
        const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#Evidence-${id}`
        const detachQuery = detachFromObservationQuery( observationId, 'relevant_evidence', iri );
        try {
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: detachQuery,
            queryId: "Detach Evidence from Observation"
          });
        } catch (e) {
          console.log(e)
          throw e
        }
      }
      
      // Delete the Evidence itself
      const query = deleteEvidenceQuery(id);
      try {
        await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: "Delete Evidence"
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      return id;
    },
    editEvidence: async (_, {id, input}, {dbName, dataSources, selectMap}) => {
      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/assessment/common#Evidence-${id}`,
        "http://csrc.nist.gov/ns/oscal/assessment/common#Evidence",
        input,
        evidencePredicateMap
      )
      await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update Characterization"
      });
      const select = selectEvidenceQuery(id, selectMap.getNode("editEvidence"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select Evidence",
        singularizeSchema
      });
      const reducer = getReducer("EVIDENCE");
      return reducer(result[0]);
    },
  },
  Evidence: {
    links: async (parent, args, {dbName, dataSources, selectMap}) => {
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
    remarks: async (parent, args, {dbName, dataSources, selectMap}) => {
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
              queryId: "Select Remark",
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

export default evidenceResolvers;