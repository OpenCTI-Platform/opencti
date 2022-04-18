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
  insertRiskResponseQuery,
  selectRiskResponseQuery,
  selectAllRiskResponses,
  deleteRiskResponseQuery,
  selectOscalTaskByIriQuery,
  selectOriginByIriQuery,
  riskResponsePredicateMap,
} from './sparql-query.js';


const riskResponseResolvers = {
  Query: {
    riskResponses: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllRiskResponses(selectMap.getNode("node"), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Risk Response List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer("RISK-RESPONSE");
        let limit, offset, limitSize, offsetSize;
        limitSize = limit = (args.first === undefined ? response.length : args.first) ;
        offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
        let riskResponseList ;
        if (args.orderedBy !== undefined ) {
          riskResponseList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          riskResponseList = response;
        }

        if (offset > riskResponseList.length) return null;

        // for each Risk Response in the result set
        for (let riskResponse of riskResponseList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (riskResponse.id === undefined || riskResponse.id == null ) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${riskResponse.iri} missing field 'id'; skipping`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(riskResponse, args.filters, args.filterMode) ) {
              continue
            }
          }

          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: risk.iri,
              node: reducer(riskResponse),
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
            globalCount: riskResponseList.length,
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
    riskResponse: async (_, {id}, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectRiskResponseQuery(id, selectMap.getNode("riskResponse"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Risk Response",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer("RISK-RESPONSE");
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
    createRiskResponse: async ( _, {input}, {dbName, selectMap, dataSources} ) => {
      // Setup to handle embedded objects to be created
      let origins, assets, tasks, riskId;
      if (input.origins !== undefined) origins = input.origins;
      if (input.required_assets !== undefined) assets = input.required_assets;
      if (input.tasks !== undefined) tasks = input.tasks;
      if (input.risk_id !== undefined) riskId = input.risk_id;

      // create the Risk Response
      const {id, query} = insertRiskResponseQuery(input);
      try {
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: "Create Risk Response"
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      // add the Risk Response to the Risk
      if (riskId !== undefined && riskId !== null) {
        const attachQuery = attachToRiskQuery( riskId, 'remediation', iri );
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: attachQuery,
            queryId: "Add Remediation to Risk"
          });
        } catch (e) {
          console.log(e)
          throw e
        }  
      }

      // create any assets supplied and attach them to the Risk Response
      if (assets !== undefined && assets !== null ) {
        // create the Task
        // attach task to the Risk Response
      }
      // create any task supplied and attach them to the Risk Response
      if (tasks !== undefined && tasks !== null ) {
        // create the task
        // attach task ot the Risk Response
      }
      // create any origins supplied and attach them to the Risk Response
      if (origins !== undefined && origins !== null ) {
        // create the origin
        // attach origin ot the Characterization
      }

      // retrieve information about the newly created Characterization to return to the user
      const select = selectRiskResponseQuery(id, selectMap.getNode("createRiskResponse"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: "Select Risk Response",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      const reducer = getReducer("RISK-RESPONSE");
      return reducer(response[0]);
    },
    deleteRiskResponse: async ( _, {riskId, id}, {dbName, dataSources} ) => {
      // check that the risk response exists
      const sparqlQuery = selectRiskResponseQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Risk Response",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      let reducer = getReducer("RISK-RESPONSE");
      const riskResponse = (reducer(response[0]));
      
      // Delete any attached origins
      if (riskResponse.hasOwnProperty('origins_iri')) {
        for (const originIri of riskResponse.origins_iri) {
          const originQuery = deleteOriginByIriQuery(originIri);
          try {
            await dataSources.Stardog.delete({
              dbName,
              sparqlQuery: originQuery,
              queryId: "Delete Origin from Risk Response"
            });
          } catch (e) {
            console.log(e)
            throw e
          }    
        }
      }

      // detach the Risk Response from the Risk
      if (riskId !== undefined && riskId !== null) {
        const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#RiskResponse-${id}`
        const detachQuery = detachFromRiskQuery( riskId, 'remediations', iri );
        try {
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: detachQuery,
            queryId: "Detach Risk Response from Risk"
          });
        } catch (e) {
          console.log(e)
          throw e
        }
      }
      
      // Delete the characterization itself
      const query = deleteRiskResponseQuery(id);
      try {
        await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: "Delete Risk Response"
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      return id;
    },
    editRiskResponse: async (_, {id, input}, {dbName, dataSources, selectMap}) => {
      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/assessment/common#RiskResponse-${id}`,
        "http://csrc.nist.gov/ns/oscal/assessment/common#RiskResponse",
        input,
        riskResponsePredicateMap
      )
      await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update Risk Response"
      });
      const select = selectRiskResponseQuery(id, selectMap.getNode("editRiskResponse"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select Risk Response",
        singularizeSchema
      });
      const reducer = getReducer("RISK-RESPONSE");
      return reducer(result[0]);
    },
  },
  // field-level resolvers
  RiskResponse: {
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
    required_assets: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.required_assets_iri === undefined) return [];
      let iriArray = parent.required_assets_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer("REQUIRED-ASSET");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('RequiredAsset')) {
            continue;
          }
          const sparqlQuery = selectRequiredAssetByIriQuery(iri, selectMap.getNode("required_assets"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Required Asset",
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
    tasks: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.tasks_iri === undefined) return [];
      let iriArray = parent.tasks_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer("TASK");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Task')) {
            continue;
          }
          const sparqlQuery = selectOscalTaskByIriQuery(iri, selectMap.getNode("tasks"));
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
  }
}

export default riskResponseResolvers;
