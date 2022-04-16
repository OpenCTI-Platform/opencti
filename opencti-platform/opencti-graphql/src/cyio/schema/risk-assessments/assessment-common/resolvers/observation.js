import { riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import {compareValues, updateQuery, filterValues} from '../../../utils.js';
import {UserInputError} from "apollo-server-express";
import {
  selectLabelByIriQuery,
  selectExternalReferenceByIriQuery,
  selectNoteByIriQuery,
  getReducer as getGlobalReducer,
} from '../../../global/resolvers/sparql-query.js';
import {
  getReducer, 
  insertObservationQuery,
  selectObservationQuery,
  selectAllObservations,
  deleteObservationQuery,
  attachToObservationQuery,
  selectEvidenceByIriQuery,
  insertEvidencesQuery,
  deleteEvidenceByIriQuery,
  selectOriginByIriQuery,
  selectSubjectByIriQuery,
  observationPredicateMap,
} from './sparql-query.js';


const observationResolvers = {
  Query: {
    observations: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllObservations(selectMap.getNode("node"), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Observation List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer("OBSERVATION");
        let limit, offset, limitSize, offsetSize;
        limitSize = limit = (args.first === undefined ? response.length : args.first) ;
        offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
        let observationList ;
        if (args.orderedBy !== undefined ) {
          observationList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          observationList = response;
        }

        if (offset > observationList.length) return null;

        // for each Risk in the result set
        for (let observation of observationList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (observation.id === undefined || observation.id == null ) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${observation.iri} missing field 'id'; skipping`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(observation, args.filters, args.filterMode) ) {
              continue
            }
          }

          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: observation.iri,
              node: reducer(observation),
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
            globalCount: observationList.length,
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
    observation: async (_, {id}, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectObservationQuery(id, selectMap.getNode("observation"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Observation",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer("OBSERVATION");
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
    createObservation: async ( _, {input}, {dbName, selectMap, dataSources} ) => {
      // Setup to handle embedded objects to be created
      let evidence, origins, subjects;
      if (input.relevant_evidence !== undefined) {
        evidence = input.relevant_evidence;
        delete input.relevant_evidence;
      }
      if (input.origins !== undefined) {
        origins = input.origins;
        delete input.origins;
      }
      if (input.subjects !== undefined) {
        subjects = input.subjects;
        delete input.subjects;
      }

      // create the Observation
      const {id, query} = insertObservationQuery(input);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: query,
        queryId: "Create Observation"
      });

      //add the Observation to parent

      // create any evidence supplied and attach them to the Observation
      if (evidence !== undefined && evidence !== null){
        // create the Evidence
        const { evidenceIris, query } = insertEvidencesQuery( evidence );
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: query,
            queryId: "Create Evidence of Observation"
          });
        } catch (e) {
          console.log(e)
          throw e
        }

        // attach Evidence to the Observation
        const evidenceAttachQuery = attachToObservationQuery(id, 'relevant_evidence', evidenceIris );
        try {
          await dataSources.Stardog.create({
            dbName,
            queryId: "Add Evidence to Observation",
            sparqlQuery: evidenceAttachQuery
          });
        } catch (e) {
          console.log(e)
          throw e
        }
      }

      // create any origins supplied and attach them to the Characterization
      if (origins !== undefined && origins !== null ) {
        // create the origin
        // attach origin ot the Characterization
      }

      // create any Subjects supplied and attach them to the Characterization
      if (subjects !== undefined && subjects !== null ) {
        // create the subject
        // attach subject ot the Characterization
      }

      // retrieve information about the newly created Observation to return to the user
      const select = selectObservationQuery(id, selectMap.getNode("createObservation"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: "Select Observation",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      const reducer = getReducer("OBSERVATION");
      return reducer(response[0]);
    },
    deleteObservation: async ( _, {id}, {dbName, dataSources} ) => {
      // check that the observation exists
      const sparqlQuery = selectObservationQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Observation",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      let reducer = getReducer("OBSERVATION");
      const observation = (reducer(response[0]));

      // Delete any attached evidence
      if (observation.hasOwnProperty('relevant_evidence_iri')) {
        for (const evidenceIri of observation.relevant_evidence_iri) {
          const evidenceQuery = deleteEvidenceByIriQuery(evidenceIri);
          try {
            await dataSources.Stardog.delete({
              dbName,
              sparqlQuery: evidenceQuery,
              queryId: "Delete the Evidence from the Observation"
            });
          } catch (e) {
            console.log(e)
            throw e
          }
        }
      }
      // Delete any attached origins
      if (observation.hasOwnProperty('origins_iri')) {
        for (const originIri of observation.origins_iri) {
          const originQuery = deleteOriginByIriQuery(originIri);
          try {
            await dataSources.Stardog.delete({
              dbName,
              sparqlQuery: originQuery,
              queryId: "Delete Origin from Observation"
            });
          } catch (e) {
            console.log(e)
            throw e
          }    
        }
      }

      // Delete any attached subjects
      if (observation.hasOwnProperty('subjects_iri')) {
        for (const subjectIri of observation.subjects_iri) {
          const subjectQuery = deleteSubjectByIriQuery(subjectIri);
          try {
            await dataSources.Stardog.delete({
              dbName,
              sparqlQuery: subjectQuery,
              queryId: "Delete Subject from Observation"
            });
          } catch (e) {
            console.log(e)
            throw e
          }    
        }
      }

      // Detach the Observation from the parent

      // Delete the Observation itself
      const query = deleteObservationQuery(id);
      try {
        await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: "Delete Observation"
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      return id;
    },
    editObservation: async (_, {id, input}, {dbName, dataSources, selectMap}) => {
      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/assessment/common#Observation-${id}`,
        "http://csrc.nist.gov/ns/oscal/assessment/common#Observation",
        input,
        observationPredicateMap
      )
      await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update Observation"
      });
      const select = selectObservationQuery(id, selectMap.getNode("editObservation"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select Observation",
        singularizeSchema
      });
      const reducer = getReducer("OBSERVATION");
      return reducer(result[0]);
    },
  },
  // field-level resolvers
  Observation: {
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
    origins:async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.origins_iri === undefined) return [];
      let iriArray = parent.origins_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer("ORIGIN");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Origin')) {
            continue;
          }
          const sparqlQuery = selectOriginByIriQuery(iri, selectMap.getNode("origins"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Origin",
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
    subjects: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.subjects_iri === undefined) return [];
      let iriArray = parent.subjects_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer("SUBJECT");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Subject')) {
            continue;
          }
          const sparqlQuery = selectSubjectByIriQuery(iri, selectMap.getNode("subjects"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Subject",
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
    relevant_evidence: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.relevant_evidence_iri === undefined) return [];
      let iriArray = parent.relevant_evidence_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer("EVIDENCE");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Evidence')) {
            continue;
          }
          const sparqlQuery = selectEvidenceByIriQuery(iri, selectMap.getNode("relevant_evidence"));
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
  }
}

export default observationResolvers;
