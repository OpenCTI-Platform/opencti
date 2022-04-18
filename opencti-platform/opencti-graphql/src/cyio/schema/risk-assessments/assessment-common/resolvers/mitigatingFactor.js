import {riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
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
  insertMitigatingFactorQuery,
  selectMitigatingFactorQuery,
  selectAllMitigatingFactors,
  deleteMitigatingFactorQuery,
  attachToMitigatingFactorQuery,
  attachToRiskQuery,
  detachFromRiskQuery,
  insertSubjectsQuery,
  selectSubjectByIriQuery,
  deleteSubjectByIriQuery,
  mitigatingFactorPredicateMap,
} from './sparql-query.js';

const mitigatingFactorResolvers = {
  Query: {
    mitigatingFactors: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllMitigatingFactors(selectMap.getNode("node"), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Mitigating Factor List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer("MITIGATING-FACTOR");
        let limit, offset, limitSize, offsetSize;
        limitSize = limit = (args.first === undefined ? response.length : args.first) ;
        offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
        let factorList ;
        if (args.orderedBy !== undefined ) {
          factorList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          factorList = response;
        }

        if (offset > factorList.length) return null;

        // for each Mitigating Factor in the result set
        for (let factor of factorList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (factor.id === undefined || factor.id == null ) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${factor.iri} missing field 'id'; skipping`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(factor, args.filters, args.filterMode) ) {
              continue
            }
          }

          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: factor.iri,
              node: reducer(factor),
            }
            edges.push(edge)
            limit--;
          }
        }
        if (edges.length === 0 ) return null;
        // Need to adjust limitSize in case filters were used
        if (args !== undefined && 'filters' in args && args.filters !== null) limitSize++;
        return {
          pageInfo: {
            startCursor: edges[0].cursor,
            endCursor: edges[edges.length-1].cursor,
            hasNextPage: (edges.length < limitSize ? false : true),
            hasPreviousPage: (offsetSize > 0 ? true : false),
            globalCount: factorList.length,
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
    mitigatingFactor: async (_, {id}, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectMitigatingFactorQuery(id, selectMap.getNode("mitigatingFactor"));
      let response;
      try {
          response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Mitigating Factor",
          singularizeSchema
          });
      } catch (e) {
          console.log(e)
          throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
          const reducer = getReducer("MITIGATING-FACTOR");
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
    createMitigatingFactor: async ( _, {riskId, input}, {dbName, selectMap, dataSources} ) => {
      // Setup to handle embedded objects to be created
      let subjects;
      if (input.subjects !== undefined) subjects = input.subjects;

      // create the Mitigating Factor
      const {iri, id, query} = insertMitigatingFactorQuery(input);
      try {
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: "Create Mitigating Factor"
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      // add the Mitigating Factor to the Risk
      if (riskId !== undefined && riskId !== null) {
        const attachQuery = attachToRiskQuery( riskId, 'mitigating_factors', iri );
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: attachQuery,
            queryId: "Add Mitigating Factor to Risk"
          });
        } catch (e) {
          console.log(e)
          throw e
        }  
      }
      
      // create any subjects supplied and attach them to the Mitigating Factor
      if ( subjects !== undefined && subjects !== null ) {
        // create the Subjects
        const { subjectIris, query } = insertSubjectsQuery( subjects );
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: query,
            queryId: "Create Subjects of Mitigating Factor"
          });
        } catch (e) {
          console.log(e)
          throw e
        }

        // attach Subjects to the Mitigating Factor
        const factorAttachQuery = attachToMitigatingFactorQuery(id, 'subjects', subjectIris );
        try {
          await dataSources.Stardog.create({
            dbName,
            queryId: "Add Subject(s) to MitigatingFactor",
            sparqlQuery: factorAttachQuery
          });
        } catch (e) {
          console.log(e)
          throw e
        }
      }

      // retrieve information about the newly created MitigatingFactor to be returned to the caller
      const select = selectMitigatingFactorQuery(id, selectMap.getNode("createMitigatingFactor"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: "Select MitigatingFactor",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      const reducer = getReducer("MITIGATING-FACTOR");
      return reducer(response[0]);
    },
    deleteMitigatingFactor: async ( _, {riskId}, {dbName, dataSources,} ) => {
      // check that the MitigatingFactor exists
      const sparqlQuery = selectMitigatingFactorQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select MitigatingFactor",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      let reducer = getReducer("MITIGATING-FACTOR");
      const mitigatingFactor = (reducer(response[0]));

      // Delete any attached subjects
      if (mitigatingFactor.hasOwnProperty('subjects_iri')) {
        for (const subjectIri of mitigatingFactor.subjects_iri) {
          const subjectQuery = deleteSubjectByIriQuery(subjectIri);
          try {
            await dataSources.Stardog.delete({
              dbName,
              sparqlQuery: subjectQuery,
              queryId: "Delete Subject from MitigatingFactor"
            });
          } catch (e) {
            console.log(e)
            throw e
          }
        }
      }

      // detach the MitigatingFactor from the Risk
      if (riskId !== undefined && riskId !== null) {
        const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#MitigatingFactor-${id}`
        const detachQuery = detachFromRiskQuery( riskId, 'mitigating_factors', iri );
        try {
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: detachQuery,
            queryId: "Detach MitigatingFactor from Risk"
          });
        } catch (e) {
          console.log(e)
          throw e
        }
      }
      
      // Delete the MitigatingFactor itself
      const query = deleteMitigatingFactorQuery(id);
      try {
        await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: "Delete MitigatingFactor"
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      return id;
    },
    editMitigatingFactor: async (_, {id, input}, {dbName, dataSources, selectMap}) => {
      // check that the MitigatingFactor exists
      const sparqlQuery = selectMitigatingFactorQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select MitigatingFactor",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/assessment/common#MitigatingFactor-${id}`,
        "http://csrc.nist.gov/ns/oscal/assessment/common#MitigatingFactor",
        input,
        mitigatingFactorPredicateMap
      )
      await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update Mitigating Factor"
      });
      const select = selectMitigatingFactorQuery(id, selectMap.getNode("editMitigatingFactor"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select Mitigating Factor",
        singularizeSchema
      });
      const reducer = getReducer("MITIGATING-FACTOR");
      return reducer(result[0]);
    },
  },
  MitigatingFactor: {
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
          const sparqlQuery = selectLabelByIriQuery(iri, selectMap.getNode("links"));
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
  }
}

export default mitigatingFactorResolvers;