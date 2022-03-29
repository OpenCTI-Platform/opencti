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
  insertRiskQuery,
  selectRiskQuery,
  selectAllRisks,
  deleteRiskQuery,
  riskPredicateMap,
  selectCharacterizationByIriQuery,
  selectMitigatingFactorByIriQuery,
  selectObservationByIriQuery,
  selectRiskResponseByIriQuery,
  selectRiskLogEntryByIriQuery,
  selectOriginByIriQuery,
} from './sparql-query.js';


const riskResolvers = {
  Query: {
    risks: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllRisks(selectMap.getNode("node"), args.filters);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Risk List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer("RISK");
        let limit = (args.first === undefined ? response.length : args.first) ;
        let offset = (args.offset === undefined ? 0 : args.offset) ;
        let riskList ;
        if (args.orderedBy !== undefined ) {
          riskList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          riskList = response;
        }

        if (offset > riskList.length) return null;

        // for each Risk in the result set
        for (let risk of riskList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (risk.id === undefined || risk.id == null ) {
            console.log(`[DATA-ERROR] object ${risk.iri} is missing required properties; skipping object.`);
            continue;
          }

          // calculate the risk level
          if (risk.cvss2_base_score !== undefined || risk.cvss3_base_score !== undefined) {
            let score = risk.cvss3_base_score !== undefined ? parseFloat(risk.cvss3_base_score) : parseFloat(risk.cvss2_base_score) ;
            let riskLevel;
            if (score <= 10 && score >= 9.0) riskLevel = 'very-high';
            if (score <= 8.9 && score >= 7.0) riskLevel = 'high';
            if (score <= 6.9 && score >= 4.0) riskLevel = 'moderate';
            if (score <= 3.9 && score >= 0.1) riskLevel = 'low';
            if (score == 0) riskLevel = 'very-low';

            // add the risk level to the object
            risk.risk_level = riskLevel;
            risk.risk_score = score;

            // clean up
            delete risk.cvss20_base_score;
            delete risk.cvss20_temporal_score;
            delete risk.cvss30_base_score
            delete risk.cvss30_temporal_score;
            delete risk.exploit_available;
            delete risk.exploitability;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(risk, args.filters, args.filterMode) ) {
              continue
            }
          }

          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: risk.iri,
              node: reducer(risk),
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
            hasNextPage: (args.first > riskList.length),
            hasPreviousPage: (args.offset > 0),
            globalCount: riskList.length,
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
    risk: async (_, {id}, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectRiskQuery(id, selectMap.getNode("risk"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Risk",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer("RISK");
        let risk = response[0];

        // calculate the risk level
        if (risk.cvss2_base_score !== undefined || risk.cvss3_base_score !== undefined) {
          let score = risk.cvss3_base_score !== undefined ? parseFloat(risk.cvss3_base_score) : parseFloat(risk.cvss2_base_score) ;
          let riskLevel;
          if (score <= 10 && score >= 9.0) riskLevel = 'very-high';
          if (score <= 8.9 && score >= 7.0) riskLevel = 'high';
          if (score <= 6.9 && score >= 4.0) riskLevel = 'moderate';
          if (score <= 3.9 && score >= 0.1) riskLevel = 'low';
          if (score == 0) riskLevel = 'very-low';

          // add the risk level to the object
          risk.risk_level = riskLevel;
          risk.risk_score = score;

          // clean up
          delete risk.cvss20_base_score;
          delete risk.cvss20_temporal_score;
          delete risk.cvss30_base_score
          delete risk.cvss30_temporal_score;
          delete risk.exploit_available;
          delete risk.exploitability;
        }

        return reducer(risk);  
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
    createRisk: async ( _, {input}, {dbName, selectMap, dataSources} ) => {
      // Setup to handle embedded objects to be created
      let origins;
      if (input.origins !== undefined) {
        origins = input.origins;
        delete input.origins;
      }

      // create the Risk
      const {id, query} = insertRiskQuery(input);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: query,
        queryId: "Create Risk"
      });

      // add the Risk to its supplied parent

      // create any origins supplied and attach them to the Risk
      if (origins !== undefined && origins !== null ) {
        // create the origin
        // attach origin ot the Risk
      }

      // retrieve information about the newly created Risk to return to the user
      const select = selectRiskQuery(id, selectMap.getNode("createRisk"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select Risk",
        singularizeSchema
      });
      const reducer = getReducer("RISK");
      return reducer(result[0]);
    },
    deleteRisk: async ( _, {id}, {dbName, dataSources} ) => {
      // check that the risk exists
      const sparqlQuery = selectRiskQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Risk",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      let reducer = getReducer("RISK");
      const risk = (reducer(response[0]));

      // Delete any attached origins
      if (risk.hasOwnProperty('origins_iri')) {
        for (const originIri of risk.origins_iri) {
          const originQuery = deleteOriginByIriQuery(originIri);
          try {
            await dataSources.Stardog.delete({
              dbName,
              sparqlQuery: originQuery,
              queryId: "Delete Origin from Risk"
            });
          } catch (e) {
            console.log(e)
            throw e
          }    
        }
      }

      // Detach the Risk from the parent

      // Delete the Observation itself
      const query = deleteRiskQuery(id);
      try {
        await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: "Delete Risk"
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      return id;
    },
    editRisk: async (_, {id, input}, {dbName, dataSources, selectMap}) => {
      // check that the risk exists
      const sparqlQuery = selectRiskQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Risk",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/assessment/common#Risk-${id}`,
        "http://csrc.nist.gov/ns/oscal/assessment/common#Risk",
        input,
        riskPredicateMap
      )
      response = await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update Risk"
      });
      if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      const select = selectRiskQuery(id, selectMap.getNode("editRisk"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select Risk",
        singularizeSchema
      });
      const reducer = getReducer("RISK");
      return reducer(result[0]);
    },
  },
  // field-level resolvers
  Risk: {
    labels: async (parent, args, {dbName, dataSources, selectMap}) => {
      if (parent.labels_iri === undefined) return [];
      let iriArray = parent.labels_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("LABEL");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Label')) {
            continue;
          }
          const sparqlQuery = selectLabelByIriQuery(iri, null);
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
          const sparqlQuery = selectExternalReferenceByIriQuery(iri, null);
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
          const sparqlQuery = selectNoteByIriQuery(iri, null);
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
    origins:async (parent, args, {dbName, dataSources, selectMap}) => {
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
    threats: async (parent, args, {dbName, dataSources, selectMap}) => {
      // this is a No-Op for MVP until we get threat intelligence integrated 
      return [];
    },
    characterizations: async (parent, args, {dbName, dataSources, selectMap}) => {
      if (parent.characterizations_iri === undefined) return [];
      let iriArray = parent.characterizations_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer("CHARACTERIZATION");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Characterization')) {
            continue;
          }
          const sparqlQuery = selectCharacterizationByIriQuery(iri, selectMap.getNode('characterizations'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Characterization",
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
    mitigating_factors: async (parent, args, {dbName, dataSources, selectMap}) => {
      if (parent.mitigating_factors_iri === undefined) return [];
      let iriArray = parent.mitigating_factors_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer("MITIGATING-FACTOR");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('MitigatingFactor')) {
            continue;
          }
          const sparqlQuery = selectMitigatingFactorByIriQuery(iri, null);
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
    remediations: async (parent, args, {dbName, dataSources, selectMap}) => {
      if (parent.remediations_iri === undefined) return [];
      let iriArray = parent.remediations_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer("RISK-RESPONSE");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('RiskResponse')) {
            continue;
          }
          const sparqlQuery = selectRiskResponseByIriQuery(iri, null);
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
    risk_log: async (parent, args, {dbName, dataSources, selectMap}) => {
      if (parent.risk_log_iri === undefined) return null;
      let iriArray = parent.risk_log_iri;
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const edges = [];
        const reducer = getAssessmentReducer("RISK-LOG-ENTRY");
        let limit = (args.first === undefined ? iriArray.length : args.first) ;
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('RiskLogEntry')) continue ;
          const sparqlQuery = selectRiskLogEntryByIriQuery(iri, null);
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
          if (response === undefined) return null;
          if (Array.isArray(response) && response.length > 0) {
            if ( limit ) {
              let edge = {
                cursor: iri,
                node: reducer(response[0]),
              }
              edges.push(edge);
              limit--;
            }
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
        if (edges.length === 0 ) return null;
        return {
          pageInfo: {
            startCursor: edges[0].cursor,
            endCursor: edges[edges.length-1].cursor,
            hasNextPage: (iriArray.length > args.first ),
            hasPreviousPage: 0,
            globalCount: iriArray.length,
          },
          edges: edges,
        }
      } else {
        return null;
      }
    },
    related_observations: async (parent, args, {dbName, dataSources, selectMap}) => {
      if (parent.related_observations_iri === undefined) return [];
      let iriArray = parent.related_observations_iri;
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const edges = [];
        const reducer = getReducer("OBSERVATION");
        let limit = (args.first === undefined ? iriArray.length : args.first) ;
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Observation')) continue ;
          const sparqlQuery = selectObservationByIriQuery(iri, null);
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
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            if ( limit ) {
              let edge = {
                cursor: iri,
                node: reducer(response[0]),
              }
              edges.push(edge);
              limit--;
            }
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
        if (edges.length === 0 ) return [];
        return {
          pageInfo: {
            startCursor: edges[0].cursor,
            endCursor: edges[edges.length-1].cursor,
            hasNextPage: (iriArray.length > args.first ),
            hasPreviousPage: 0,
            globalCount: iriArray.length,
          },
          edges: edges,
        }
      } else {
        return [];
      }
    },
  }
}

export default riskResolvers;
