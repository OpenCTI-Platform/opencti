import { riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import {compareValues, updateQuery, filterValues} from '../../../utils.js';
import {UserInputError} from "apollo-server-express";
import {
  getReducer, 
  insertPOAMItemQuery,
  selectPOAMItemQuery,
  selectAllPOAMItems,
  deletePOAMItemQuery,
  poamItemPredicateMap,
  addItemToPOAM,
  removeItemFromPOAM,
} from './sparql-query.js';
import {
  selectLabelByIriQuery,
  selectExternalReferenceByIriQuery,
  selectNoteByIriQuery,
  getReducer as getGlobalReducer,
} from '../../../global/resolvers/sparql-query.js';
import {
  getReducer as getAssessmentReducer,
  selectObservationByIriQuery,
  selectRiskByIriQuery,
} from '../../assessment-common/resolvers/sparql-query.js'

const poamItemResolvers = {
  Query: {
    poamItems: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllPOAMItems(selectMap.getNode("node"), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select POAM Item List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer("POAM-ITEM");
        let limit, offset, limitSize, offsetSize;
        limitSize = limit = (args.first === undefined ? response.length : args.first) ;
        offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
        let itemList ;
        if (args.orderedBy !== undefined ) {
          itemList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          itemList = response;
        }

        if (offset > itemList.length) return null;

        // for each POAM in the result set
        for (let item of itemList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (item.id === undefined || item.id == null ) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${item.iri} missing field 'id'; skipping`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(item, args.filters, args.filterMode) ) {
              continue
            }
          }

          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: item.iri,
              node: reducer(item),
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
            globalCount: itemList.length,
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
    poamItem: async (_, {id}, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectPOAMItemQuery(id, selectMap.getNode("poam"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select POAM Item",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer("POAM-ITEM");
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
    createPOAMItem: async ( _, {poam, input}, {dbName, selectMap, dataSources} ) => {
      const {iri, id, query} = insertPOAMItemQuery(input);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: query,
        queryId: "Create POAM Item"
      });
      const attachQuery = addItemToPOAM(poam, iri);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: attachQuery,
        queryId: "Add POAM Item to POAM"
      });
      const select = selectPOAMItemQuery(id, selectMap.getNode("createPOAMItem"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select POAM Item",
        singularizeSchema
      });
      const reducer = getReducer("POAM-ITEM");
      return reducer(result[0]);
    },
    deletePOAMItem: async ( _, {poam, id}, {dbName, dataSources,} ) => {
      // remove the POAM Item from the POAM
      const relationshipQuery = removeItemFromPOAM(poam, id);
      await dataSources.Stardog.delete({
        dbName,
        sparqlQuery: relationshipQuery,
        queryId: "Delete POAM Item from POAM"
      })

      // delete the POAM Item itself
      const query = deletePOAMItemQuery(id);
      await dataSources.Stardog.delete({
        dbName,
        sparqlQuery: query,
        queryId: "Delete POAM Item"
      });
      return id;
    },
    editPOAMItem: async (_, {id, input}, {dbName, dataSources, selectMap}) => {
      // check that the risk exists
      const sparqlQuery = selectPOAMItemQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select POAM Item",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/poam#Item-${id}`,
        "http://csrc.nist.gov/ns/oscal/poam#Item",
        input,
        poamItemPredicateMap
      )
      response = await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update POAM Item"
      });
      if (response === undefined || response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      const select = selectPOAMItemQuery(id, selectMap.getNode("editPOAMItem"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select POAM Item",
        singularizeSchema
      });
      const reducer = getReducer("POAM-ITEM");
      return reducer(result[0]);
    },
  },
  // field-level resolvers
  POAMItem: {
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
          if (iri === undefined || !iri.includes('ExternalReference')) continue;
          const sparqlQuery = selectExternalReferenceByIriQuery(iri, selectMap.getNode("links"));
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
          if (iri === undefined || !iri.includes('Note')) continue;
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
    related_observations: async (parent, args, {dbName, dataSources, selectMap}) => {
      if (parent.related_observations_iri === undefined) return null;
      let iriArray = parent.related_observations_iri;
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const edges = [];
        const reducer = getAssessmentReducer("OBSERVATION");
        let limit, offset, limitSize, offsetSize;
        limitSize = limit = (args.first === undefined ? iriArray.length : args.first) ;
        offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Observation')) continue ;
          const sparqlQuery = selectObservationByIriQuery(iri, selectMap.getNode("node"));
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
            hasNextPage: (edges.length < limitSize + 1 ? false : true),
            hasPreviousPage: (offsetSize > 0 ? true : false),
            globalCount: iriArray.length,
          },
          edges: edges,
        }
      } else {
        return null;
      }
    },
    related_risks: async (parent, args, {dbName, dataSources, selectMap}) => {
      if (parent.related_risks_iri === undefined) return null;
      let iriArray = parent.related_risks_iri;
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        let edges = [];
        const reducer = getAssessmentReducer("RISK");
        let limit, offset, limitSize, offsetSize;
        limitSize = limit = (args.first === undefined ? iriArray.length : args.first) ;
        offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Risk')) continue ;
          const select = selectMap.getNode('node')
          const sparqlQuery = selectRiskByIriQuery(iri, select);
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
            let risk = response[0];

          if (risk.risk_status == 'deviation_requested' || risk.risk_status == 'deviation_approved') {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${risk.iri} invalid field value 'risk_status'; fixing`);
            risk.risk_status = risk.risk_status.replace('_', '-');
          }

          // calculate the risk level
            risk.risk_level = 'unknown';
            if (risk.cvss20_base_score !== undefined || risk.cvss30_base_score !== undefined) {
              let riskLevel;
              let score = risk.cvss30_base_score !== undefined ? parseFloat(risk.cvss30_base_score) : parseFloat(risk.cvss20_base_score) ;
              if (score <= 10 && score >= 9.0) riskLevel = 'very-high';
              if (score <= 8.9 && score >= 7.0) riskLevel = 'high';
              if (score <= 6.9 && score >= 4.0) riskLevel = 'moderate';
              if (score <= 3.9 && score >= 0.1) riskLevel = 'low';
              if (score == 0) riskLevel = 'very-low';
              risk.risk_score = score;
              risk.risk_level = riskLevel;

              // clean up
              delete risk.cvss20_base_score;
              delete risk.cvss20_temporal_score;
              delete risk.cvss30_base_score
              delete risk.cvss30_temporal_score;
              delete risk.exploit_available;
              delete risk.exploitability;
            }

            if ( limit ) {
              let edge = {
                cursor: iri,
                node: reducer(risk),
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
        // return null if no edges
        if (edges.length === 0 ) return null;
        return {
          pageInfo: {
            startCursor: edges[0].cursor,
            endCursor: edges[edges.length-1].cursor,
            hasNextPage: (edges.length < limitSize + 1 ? false : true),
            hasPreviousPage: (offsetSize > 0 ? true : false),
            globalCount: iriArray.length,
          },
          edges: edges,
        }
      } else {
        return null;
      }
    },
    occurrences:  async (parent, _, {dbName, dataSources, }) => {
      if (parent.id === undefined) {
        return 0;
      }
      const id = parent.id
      const iri = `<http://csrc.nist.gov/ns/oscal/poam#Item-${id}>`
      const sparqlQuery = `
      SELECT DISTINCT (COUNT(?related_observations) as ?occurrences)
      FROM <tag:stardog:api:context:local>
      WHERE {
        ${iri} <http://csrc.nist.gov/ns/oscal/assessment/common#related_observations> ?related_observations .
      }
      `;
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select occurrence count",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      if (response === undefined) {
        return 0;
      }
      if (Array.isArray(response) && response.length > 0) {
        return( response[0].occurrences)
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
  }
}

export default poamItemResolvers;
