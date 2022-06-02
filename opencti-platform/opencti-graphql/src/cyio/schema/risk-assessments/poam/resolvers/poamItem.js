import { riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import {compareValues, updateQuery, filterValues} from '../../../utils.js';
import {UserInputError} from "apollo-server-express";
import { calculateRiskLevel, getLatestRemediationInfo } from '../../riskUtils.js';
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
  selectAllObservations,
  selectAllRisks,
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
        let filterCount, resultCount, limit, offset, limitSize, offsetSize;
        limitSize = limit = (args.first === undefined ? response.length : args.first) ;
        offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
        filterCount = 0;
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

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(item, args.filters, args.filterMode) ) {
              continue
            }
            filterCount++;
          }

          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: item.iri,
              node: reducer(item),
            }
            edges.push(edge)
            limit--;
            if (limit === 0) break;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0 ) return null;
        let hasNextPage = false, hasPreviousPage = false;
        resultCount = itemList.length;
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
      // check that the object to be edited exists with the predicates - only get the minimum of data
      let editSelect = ['id'];
      for (let editItem of input) {
        editSelect.push(editItem.key);
      }
      const sparqlQuery = selectPOAMItemQuery(id, editSelect );
      let response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select POAM Item",
        singularizeSchema
      })
      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

      // TODO: WORKAROUND to handle UI where it DOES NOT provide an explicit operation
      for (let editItem of input) {
        if (!response[0].hasOwnProperty(editItem.key)) editItem.operation = 'add';
      }
      // END WORKAROUND

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
      if (parent.links_iri === undefined) return [];
      let iriArray = parent.links_iri;
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
      if (parent.remarks_iri === undefined) return [];
      let iriArray = parent.remarks_iri;
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
      const edges = [];
      let filterCount, resultCount, limit, offset, limitSize, offsetSize;
      filterCount = 0;
      
      // if only returning the id, then use the values already collected in the parent
      if (selectMap.getNode('node').length === 1 && selectMap.getNode('node').includes('id')) {
        if (parent.related_observation_ids !== undefined && parent.related_observation_ids.length > 0) {
          limitSize = limit = (args.first === undefined ? parent.related_observations_iri.length : args.first) ;
          offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
          resultCount = parent.related_observations_iri.length;
          for (let i = 0; i < parent.related_observations_iri.length; i++) {
            let relObservation = {
              iri: parent.related_observations_iri[i],
              id: parent.related_observation_ids[i],
              entity_type: 'observation'
            };

            if (limit) {
              let edge = {
                cursor: parent.related_observations_iri[i],
                node: relObservation,
              }
              edges.push(edge)
              limit--;
              if (limit === 0) break;
            }
          }
        }
      } else {
        // Perform a query as more info that just the uuid is to be returned
        const reducer = getAssessmentReducer("OBSERVATION");
        let sparqlQuery = selectAllObservations(selectMap.getNode('node'), args, parent );
        let response;
        try {
          response = await dataSources.Stardog.queryById({
            dbName,
            sparqlQuery,
            queryId: "Select Related Observations",
            singularizeSchema
          });
        } catch (e) {
          console.log(e)
          throw e
        }
        if (response === undefined || response.length === 0) return null;

        // Handle reporting Stardog Error
        if (typeof (response) === 'object' && 'body' in response) {
          throw new UserInputError(response.statusText, {
            error_details: (response.body.message ? response.body.message : response.body),
            error_code: (response.body.code ? response.body.code : 'N/A')
          });
        }

        limitSize = limit = (args.first === undefined ? response.length : args.first) ;
        offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
        let observationList ;
        if (args.orderedBy !== undefined ) {
          observationList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          observationList = response;
        }

        if (offset > observationList.length) return null;
        resultCount = observationList.length;
        for (let observation of observationList) {
          if (offset) {
            offset--;
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(observation, args.filters, args.filterMode) ) {
              continue
            }
            filterCount++;
          }
          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: observation.iri,
              node: reducer(observation),
            }
            edges.push(edge)
            limit--;
            if (limit === 0) break;
          }
        }
      }

      // check if there is data to be returned
      if (edges.length === 0 ) return null;
      let hasNextPage = false, hasPreviousPage = false;
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
    },
    related_risks: async (parent, args, {dbName, dataSources, selectMap}) => {
      if (parent.related_risks_iri === undefined) return null;
      let edges = [];
      let filterCount, resultCount, limit, offset, limitSize, offsetSize;
      filterCount = 0;

      // if only returning the id, then use the values already collected in the parent
      if (selectMap.getNode('node').length === 1 && selectMap.getNode('node').includes('id')) {
        if (parent.related_risk_ids !== undefined || parent.related_risk_ids.length > 0) {
          limitSize = limit = (args.first === undefined ? parent.related_risks_iri.length : args.first) ;
          offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
          resultCount = parent.related_risks_iri.length;
          for (let i = 0; i < parent.related_risks_iri.length; i++) {
            let risk = {
              iri: parent.related_risks_iri[i],
              id: parent.related_risk_ids[i],
              entity_type: 'risk'
            };

            if (limit) {
              let edge = {
                cursor: parent.related_risks_iri[i],
                node: risk,
              }
              edges.push(edge)
              limit--;
              if (limit === 0) break;
            }
          }
        }
      } else {
        // Perform a query as more info that just the uuid is to be returned
        const reducer = getAssessmentReducer("RISK");
        let sparqlQuery = selectAllRisks(selectMap.getNode('node'), args, parent);
        let response;
        try {
          response = await dataSources.Stardog.queryById({
            dbName,
            sparqlQuery,
            queryId: "Select Related risks",
            singularizeSchema
          });
        } catch (e) {
          console.log(e)
          throw e
        }
        if (response === undefined || response.length === 0) return null;

        // Handle reporting Stardog Error
        if (typeof (response) === 'object' && 'body' in response) {
          throw new UserInputError(response.statusText, {
            error_details: (response.body.message ? response.body.message : response.body),
            error_code: (response.body.code ? response.body.code : 'N/A')
          });
        }

        limitSize = limit = (args.first === undefined ? response.length : args.first) ;
        offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
        
        // update the risk level and score before sorting
        for (let risk of response) {
          risk.risk_level = 'unknown';
          if (risk.cvssV2Base_score !== undefined || risk.cvssV3Base_score !== undefined) {
            // calculate the risk level
            const {riskLevel, riskScore} = calculateRiskLevel(risk);
            risk.risk_score = riskScore;
            risk.risk_level = riskLevel;

            // clean up
            delete risk.cvssV2Base_score;
            delete risk.cvssV2Temporal_score;
            delete risk.cvssV3Base_score
            delete risk.cvssV3Temporal_score;
            delete risk.available_exploit_values;
            delete risk.exploitability_ease_values;
          }

          // retrieve most recent remediation state
          if (risk.remediation_type_values !== undefined) {
            const {responseType, lifeCycle} = getLatestRemediationInfo(risk);
            if (responseType !== undefined) risk.response_type = responseType;
            if (lifeCycle !== undefined) risk.lifecycle = lifeCycle;
            // clean up
            delete risk.remediation_type_values;
            delete risk.remediation_lifecycle_values;
          }

          // TODO: WORKAROUND fix up invalidate deviation values
          if (risk.risk_status == 'deviation_requested' || risk.risk_status == 'deviation_approved') {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${risk.iri} invalid field value 'risk_status'; fixing`);
            risk.risk_status = risk.risk_status.replace('_', '-');
          }
          // END WORKAROUND
        }

        // sort the values
        let riskList, sortBy ;
        if (args.orderedBy !== undefined ) {
          if (args.orderedBy === 'risk_level') {
            sortBy = 'risk_score';
          } else { sortBy = args.orderedBy; }
          riskList = response.sort(compareValues(sortBy, args.orderMode ));
        } else {
          riskList = response;
        }

        if (offset > riskList.length) return null;
        resultCount = riskList.length;
        // for each Risk in the result set
        for (let risk of riskList) {
          if (risk.id === undefined || risk.id == null ) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${risk.iri} missing field 'id'; skipping`);
            continue;
          }

          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && (args.filters != null && args.filters.length > 0) && args.filters[0] !== null) {
            if (!filterValues(risk, args.filters, args.filterMode) ) {
              continue
            }
            filterCount++;
          }

          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: risk.iri,
              node: reducer(risk),
            }
            edges.push(edge)
            limit--;
            if (limit === 0) break;
          }
        }
      }

      // check if there is data to be returned
      if (edges.length === 0 ) return null;
      let hasNextPage = false, hasPreviousPage = false;
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
    },
    occurrences: async (parent, _, {dbName, dataSources, }) => {
      if (parent.id === undefined) {
        return 0;
      }

      // return occurrences value from parent if already exists
      if (parent.hasOwnProperty('occurrences')) return parent.occurrences;

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
