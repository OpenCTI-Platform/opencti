import { UserInputError } from 'apollo-server-express';
import { assetSingularizeSchema as singularizeSchema, objectTypeMapping } from '../asset-mappings.js';
import { compareValues, updateQuery, filterValues, CyioError } from '../../utils.js';
import { addToInventoryQuery, deleteQuery, removeFromInventoryQuery } from '../assetUtil.js';
import {
  getReducer,
  insertSoftwareQuery,
  selectAllSoftware,
  selectSoftwareQuery,
  selectSoftwareByIriQuery,
  softwarePredicateMap,
} from './sparql-query.js';
import { selectHardwareByIriQuery, getReducer as getHardwareReducer } from '../hardware/sparql-query.js';
import {
  selectLabelByIriQuery,
  selectExternalReferenceByIriQuery,
  selectNoteByIriQuery,
  getReducer as getGlobalReducer,
} from '../../global/resolvers/sparql-query.js';
import {
  selectRiskByIriQuery,
  getReducer as getAssessmentReducer,
} from '../../risk-assessments/assessment-common/resolvers/sparql-query.js';
import { riskSingularizeSchema } from '../../risk-assessments/risk-mappings.js';
import { calculateRiskLevel, getOverallRisk } from '../../risk-assessments/riskUtils.js';

const softwareResolvers = {
  Query: {
    softwareAssetList: async (_, args, { dbName, dataSources, selectMap }) => {
      // TODO: WORKAROUND to remove argument fields with null or empty values
      if (args !== undefined) {
        for (const [key, value] of Object.entries(args)) {
          if (Array.isArray(args[key]) && args[key].length === 0) {
            delete args[key];
            continue;
          }
          if (value === null || value.length === 0) {
            delete args[key];
          }
        }
      }
      // END WORKAROUND

      let select = selectMap.getNode('node');
      const sparqlQuery = selectAllSoftware(select, args);
      const response = await dataSources.Stardog.queryAll({
        dbName,
        sparqlQuery,
        queryId: 'Select Software Assets',
        singularizeSchema,
      });

      if (response === undefined || response.length === 0) return null;
      if (Array.isArray(response) && response.length > 0) {
        // build array of edges
        const edges = [];
        const reducer = getReducer('SOFTWARE');
        let skipCount = 0;
        let filterCount;
        let resultCount;
        let limit;
        let offset;
        let limitSize;
        let offsetSize;
        limitSize = limit = args.first === undefined ? response.length : args.first;
        offsetSize = offset = args.offset === undefined ? 0 : args.offset;
        filterCount = 0;

        if (select.includes('risk_count') || select.includes('top_risk_severity')) {
          for (let asset of response) {
            // add the count of risks associated with this asset
            asset.risk_count = (asset.related_risks ? asset.related_risks.length : 0);
            if (asset.related_risks !== undefined && asset.risk_count > 0) {
              let { highestRiskScore, highestRiskSeverity } = await getOverallRisk(asset.related_risks, dbName, dataSources);
              asset.risk_score = highestRiskScore || 0;
              asset.risk_level = highestRiskSeverity || null;
              asset.top_risk_severity = asset.risk_level;
            }
          }  
        }

        let assetList;
        let sortBy;
        if (args.orderedBy !== undefined) {
          if (args.orderedBy === 'top_risk_severity') {
            sortBy = 'risk_score';
          } else {
            sortBy = args.orderedBy;
          }
          assetList = response.sort(compareValues(sortBy, args.orderMode));
        } else {
          assetList = response;
        }

        if (offset > assetList.length) return null;

        for (const asset of assetList) {
          if (asset.id === undefined || asset.id == null) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${asset.iri} missing field 'id'; skipping`);
            skipCount++;
            continue;
          }

          // skip down past the offset
          if (offset) {
            offset--;
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(asset, args.filters, args.filterMode)) {
              continue;
            }
            filterCount++;
          }

          // check to make sure not to return more than requested
          if (limit) {
            const edge = {
              cursor: asset.iri,
              node: reducer(asset),
            };
            if (edge.node.name === undefined) {
              console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${asset.iri} missing field 'name'`);
            }
            edges.push(edge);
            limit--;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0) return null;
        let hasNextPage = false;
        let hasPreviousPage = false;
        resultCount = assetList.length - skipCount;
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
    softwareAsset: async (_, { id }, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectSoftwareQuery(id, selectMap.getNode('softwareAsset'));
      const reducer = getReducer('SOFTWARE');
      const response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: 'Select Software Asset',
        singularizeSchema,
      });
      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const first = response[0];
        if (first === undefined) return null;
        return reducer(first);
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
    createSoftwareAsset: async (_, { input }, { dbName, dataSources, selectMap }) => {
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

      const { iri, id, query } = insertSoftwareQuery(input);
      await dataSources.Stardog.create({ dbName, queryId: 'Insert Software Asset', sparqlQuery: query });
      const connectQuery = addToInventoryQuery(iri);
      await dataSources.Stardog.create({ dbName, queryId: 'Insert to Inventory', sparqlQuery: connectQuery });

      // retrieve information about the newly created Software to return to the user
      const select = selectSoftwareByIriQuery(iri, selectMap.getNode('createSoftwareAsset'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: 'Select Software',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      const reducer = getReducer('SOFTWARE');
      return reducer(response[0]);
    },
    deleteSoftwareAsset: async (_, { id }, { dbName, dataSources }) => {
      // check that the ComputingDevice exists
      const sparqlQuery = selectSoftwareQuery(id, ['id']);
      const response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: 'Select Software',
        singularizeSchema,
      });
      if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);
      const relationshipQuery = removeFromInventoryQuery(response[0].iri);
      await dataSources.Stardog.delete({ dbName, sparqlQuery: relationshipQuery, queryId: 'Remove from Inventory' });
      const query = deleteQuery(id);
      await dataSources.Stardog.delete({ dbName, sparqlQuery: query, queryId: 'Delete Software Asset' });
      return id;
    },
    editSoftwareAsset: async (_, { id, input }, { dbName, dataSources, selectMap }) => {
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

      const sparqlQuery = selectSoftwareQuery(id, editSelect);
      const response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: 'Select Software',
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
        `http://scap.nist.gov/ns/asset-identification#Software-${id}`,
        'http://scap.nist.gov/ns/asset-identification#Software',
        input,
        softwarePredicateMap
      );
      if (query != null) {
        await dataSources.Stardog.edit({
          dbName,
          sparqlQuery: query,
          queryId: 'Update Software Asset',
        });
      }

      // retrieve the updated contents
      const select = selectSoftwareQuery(id, selectMap.getNode('editSoftwareAsset'));
      let result;
      try {
        result = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: 'Select Software',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      const reducer = getReducer('SOFTWARE');
      return reducer(result[0]);
    },
  },
  // field-level resolvers
  SoftwareAsset: {
    labels: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.labels_iri === undefined) return [];
      const iriArray = parent.labels_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer('LABEL');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Label')) continue;
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
    external_references: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.ext_ref_iri === undefined) return [];
      const iriArray = parent.ext_ref_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer('EXTERNAL-REFERENCE');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('ExternalReference')) continue;
          const sparqlQuery = selectExternalReferenceByIriQuery(iri, selectMap.getNode('external_references'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select External Reference',
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
    notes: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.notes_iri === undefined) return [];
      const iriArray = parent.notes_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer('NOTE');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Note')) continue;
          const sparqlQuery = selectNoteByIriQuery(iri, selectMap.getNode('notes'));
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
    installed_on: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.os_installed_on === undefined && parent.sw_installed_on === undefined) return [];
      let iriArray = [];
      if (parent.os_installed_on) iriArray = iriArray.concat(parent.os_installed_on);
      if (parent.sw_installed_on) iriArray = iriArray.concat(parent.sw_installed_on);
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getHardwareReducer('HARDWARE-DEVICE');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Hardware')) continue;
          const select = selectMap.getNode('installed_on');
          const sparqlQuery = selectHardwareByIriQuery(iri, select);
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Hardware',
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
    related_risks: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.related_risks_iri === undefined) return [];
      const iriArray = parent.related_risks_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getAssessmentReducer('RISK');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Risk')) continue;
          const select = selectMap.getNode('related_risks');
          const sparqlQuery = selectRiskByIriQuery(iri, select);
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Risk',
              singularizeSchema: riskSingularizeSchema,
            });
          } catch (e) {
            console.log(e);
            throw e;
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            let risk = response[0];

            // Convert date field values that are represented as JavaScript Date objects
            if (risk.first_seen !== undefined) {
              if (risk.first_seen instanceof Date) risk.first_seen = risk.first_seen.toISOString();
            }
            if (risk.last_seen !== undefined) {
              if (risk.last_seen instanceof Date) risk.last_seen = risk.last_seen.toISOString();
            }

            // calculate the risk level
            risk.risk_level = 'unknown';
            if (risk.cvssV2Base_score !== undefined || risk.cvssV3Base_score !== undefined) {
              const { riskLevel, riskScore } = calculateRiskLevel(risk);
              risk.risk_score = riskScore;
              risk.risk_level = riskLevel;
            }
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
  // Map enum GraphQL values to data model required values
  FamilyType: {
    windows: 'windows',
    linux: 'linux',
    macos: 'macos',
    other: 'other',
  },
  SoftwareKind: {
    __resolveType: (item) => {
      return objectTypeMapping[item.entity_type];
    },
  },
};

export default softwareResolvers;
