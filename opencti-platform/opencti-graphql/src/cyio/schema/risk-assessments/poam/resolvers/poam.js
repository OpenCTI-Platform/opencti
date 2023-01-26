import { UserInputError } from 'apollo-server-express';
import { riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import { compareValues, updateQuery, filterValues, generateId, OSCAL_NS, CyioError } from '../../../utils.js';
import { calculateRiskLevel, getLatestRemediationInfo, convertToProperties } from '../../riskUtils.js';
import {
  getReducer,
  insertPOAMQuery,
  selectPOAMQuery,
  selectAllPOAMs,
  deletePOAMQuery,
  attachToPOAMQuery,
  detachFromPOAMQuery,
  selectAllPOAMItems,
  selectPOAMLocalDefinitionByIriQuery,
  poamPredicateMap,
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
  selectAssessmentAssetByIriQuery,
  riskPredicateMap,
} from '../../assessment-common/resolvers/sparql-query.js';
import {
  insertRolesQuery,
  getReducer as getCommonReducer,
  selectAllLocations,
  selectAllParties,
  selectAllRoles,
  selectAllResponsibleParties,
  partyPredicateMap,
  responsiblePartyPredicateMap,
} from '../../oscal-common/resolvers/sparql-query.js';
import { selectAllComponents, convertAssetToComponent } from '../../component/resolvers/sparql-query.js';
import { selectAllInventoryItems, convertAssetToInventoryItem } from '../../inventory-item/resolvers/sparql-query.js';

const poamResolvers = {
  Query: {
    poams: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllPOAMs(selectMap.getNode('node'), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: 'Select POAM List',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer('POAM');
        let filterCount;
        let resultCount;
        let limit;
        let offset;
        let limitSize;
        let offsetSize;
        limitSize = limit = args.first === undefined ? response.length : args.first;
        offsetSize = offset = args.offset === undefined ? 0 : args.offset;
        filterCount = 0;
        let poamList;
        if (args.orderedBy !== undefined) {
          poamList = response.sort(compareValues(args.orderedBy, args.orderMode));
        } else {
          poamList = response;
        }

        if (offset > poamList.length) return null;

        // for each POAM in the result set
        for (const poam of poamList) {
          // skip down past the offset
          if (offset) {
            offset--;
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(poam, args.filters, args.filterMode)) {
              continue;
            }
            filterCount++;
          }

          // if haven't reached limit to be returned
          if (limit) {
            const edge = {
              cursor: poam.iri,
              node: reducer(poam),
            };
            edges.push(edge);
            limit--;
            if (limit === 0) break;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0) return null;
        let hasNextPage = false;
        let hasPreviousPage = false;
        resultCount = poamList.length;
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
      }
    },
    poam: async (_, { id }, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectPOAMQuery(id, selectMap.getNode('poam'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select POAM',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer('POAM');
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
    createPOAM: async (_, { input }, { dbName, selectMap, dataSources }) => {
      // Setup to handle embedded objects to be created
      let roles;
      let locations;
      let parties;
      let responsibleParties;
      if (input.roles !== undefined) {
        roles = input.roles;
        delete input.roles;
      }
      if (input.locations !== undefined) {
        locations = input.locations;
        delete input.locations;
      }
      if (input.parties !== undefined) {
        parties = input.parties;
        delete input.parties;
      }
      if (input.responsible_parties !== undefined) {
        responsibleParties = input.responsible_parties;
        delete input.responsible_parties;
      }

      // Create the POAM
      const { id, query } = insertPOAMQuery(input);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: query,
        queryId: 'Create POAM',
      });

      // create any roles supplied and attach them to the POAM
      if (roles !== undefined && roles !== null) {
        // create the roles
        const { roleIris, query } = insertRolesQuery(roles);
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: query,
            queryId: 'Create Roles for the POAM',
          });
        } catch (e) {
          console.log(e);
          throw e;
        }

        // attach roles to the POAM
        const roleAttachQuery = attachToPOAMQuery(id, 'roles', roleIris);
        try {
          await dataSources.Stardog.create({
            dbName,
            queryId: 'Add role to POAM',
            sparqlQuery: roleAttachQuery,
          });
        } catch (e) {
          console.log(e);
          throw e;
        }
      }

      // TODO: create any location supplied and attach them to the POAM
      if (locations !== undefined && locations !== null) {
        // create the locations
        // attach locations to the POAM
      }
      // TODO: create any parties supplied and attach them to the POAM
      if (parties !== undefined && parties !== null) {
        // create the parties
        // attach parties to the POAM
      }
      // TODO: create any responsible parties supplied and attach them to the POAM
      if (responsibleParties !== undefined && responsibleParties !== null) {
        // create the responsible parties
        // attach responsible parties to the POAM
      }

      // retrieve information about the newly created POAM to return to the user
      const select = selectPOAMQuery(id, selectMap.getNode('createPOAM'));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: 'Select POAM',
        singularizeSchema,
      });
      const reducer = getReducer('POAM');
      return reducer(result[0]);
    },
    deletePOAM: async (_, { id }, { dbName, dataSources }) => {
      // check that the risk exists
      const sparqlQuery = selectPOAMQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select POAM',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);
      const reducer = getReducer('POAM');
      const poam = reducer(response[0]);

      // Detach any attached roles
      if (poam.hasOwnProperty('roles_iri')) {
        for (const roleIri of poam.roles_iri) {
          const roleQuery = detachFromPOAMQuery(id, 'roles', roleIri);
          try {
            await dataSources.Stardog.delete({
              dbName,
              sparqlQuery: roleQuery,
              queryId: 'Detach Role from POAM',
            });
          } catch (e) {
            console.log(e);
            throw e;
          }
        }
      }

      const query = deletePOAMQuery(id);
      await dataSources.Stardog.delete({
        dbName,
        sparqlQuery: query,
        queryId: 'Delete POAM',
      });
      return id;
    },
    editPOAM: async (_, { id, input }, { dbName, dataSources, selectMap }) => {
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

      const sparqlQuery = selectPOAMQuery(id, editSelect);
      const response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: 'Select POAM',
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
        `http://csrc.nist.gov/ns/oscal/common#POAM-${id}`,
        'http://csrc.nist.gov/ns/oscal/common#POAM',
        input,
        poamPredicateMap
      );
      if (query !== null) {
        let response;
        try {
          response = await dataSources.Stardog.edit({
            dbName,
            sparqlQuery: query,
            queryId: 'Update OSCAL POAM',
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

      const select = selectPOAMQuery(id, selectMap.getNode('editPOAM'));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: 'Select POAM',
        singularizeSchema,
      });
      const reducer = getReducer('POAM');
      return reducer(result[0]);
    },
  },
  // field-level resolvers
  POAM: {
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
          if (response === undefined || (Array.isArray(response) && response.length === 0)) {
            console.error(`[CYIO] NON-EXISTENT: (${dbName}) '${iri}'; skipping entity`);
            continue;
          }
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
          if (iri === undefined || !iri.includes('ExternalReference')) continue;
          const sparqlQuery = selectExternalReferenceByIriQuery(iri, selectMap.getNode('links'));
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
          if (response === undefined || (Array.isArray(response) && response.length === 0)) {
            console.error(`[CYIO] NON-EXISTENT: (${dbName}) '${iri}'; skipping entity`);
            continue;
          }
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
          if (iri === undefined || !iri.includes('Note')) continue;
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
          if (response === undefined || (Array.isArray(response) && response.length === 0)) {
            console.error(`[CYIO] NON-EXISTENT: (${dbName}) '${iri}'; skipping entity`);
            continue;
          }
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
    revisions: async (_parent, _args, { _dbName, _dataSources, _selectMap }) => {
      // TODO: Add implementation retrieval of an array of revisions
    },
    roles: async (parent, args, { dbName, dataSources, selectMap }) => {
      if (parent.roles_iri === undefined) return null;
      const reducer = getCommonReducer('ROLE');
      const edges = [];
      const sparqlQuery = selectAllRoles(selectMap.getNode('node'), args, parent);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select All Roles',
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

      let filterCount;
      let resultCount;
      let limit;
      let offset;
      let limitSize;
      let offsetSize;
      limitSize = limit = args.first === undefined ? response.length : args.first;
      offsetSize = offset = args.offset === undefined ? 0 : args.offset;
      filterCount = 0;
      let roleList;
      if (args.orderedBy !== undefined) {
        roleList = response.sort(compareValues(args.orderedBy, args.orderMode));
      } else {
        roleList = response;
      }

      if (offset > roleList.length) return null;
      resultCount = roleList.length;
      for (const role of roleList) {
        if (offset) {
          offset--;
          continue;
        }

        // filter out non-matching entries if a filter is to be applied
        if ('filters' in args && args.filters != null && args.filters.length > 0) {
          if (!filterValues(role, args.filters, args.filterMode)) {
            continue;
          }
          filterCount++;
        }
        // if haven't reached limit to be returned
        if (limit) {
          const edge = {
            cursor: role.iri,
            node: reducer(role),
          };
          edges.push(edge);
          limit--;
          if (limit === 0) break;
        }
      }

      // check if there is data to be returned
      if (edges.length === 0) return null;
      let hasNextPage = false;
      let hasPreviousPage = false;
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
    },
    locations: async (parent, args, { dbName, dataSources, selectMap }) => {
      if (parent.locations_iri === undefined) return null;
      const reducer = getCommonReducer('LOCATION');
      const edges = [];
      const sparqlQuery = selectAllLocations(selectMap.getNode('node'), args, parent);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select All Locations',
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

      let filterCount;
      let resultCount;
      let limit;
      let offset;
      let limitSize;
      let offsetSize;
      limitSize = limit = args.first === undefined ? response.length : args.first;
      offsetSize = offset = args.offset === undefined ? 0 : args.offset;
      filterCount = 0;
      let locationList;
      if (args.orderedBy !== undefined) {
        locationList = response.sort(compareValues(args.orderedBy, args.orderMode));
      } else {
        locationList = response;
      }

      if (offset > locationList.length) return null;
      resultCount = locationList.length;
      for (const location of locationList) {
        if (offset) {
          offset--;
          continue;
        }

        // filter out non-matching entries if a filter is to be applied
        if ('filters' in args && args.filters != null && args.filters.length > 0) {
          if (!filterValues(location, args.filters, args.filterMode)) {
            continue;
          }
          filterCount++;
        }
        // if haven't reached limit to be returned
        if (limit) {
          const edge = {
            cursor: location.iri,
            node: reducer(location),
          };
          edges.push(edge);
          limit--;
          if (limit === 0) break;
        }
      }

      // check if there is data to be returned
      if (edges.length === 0) return null;
      let hasNextPage = false;
      let hasPreviousPage = false;
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
    },
    parties: async (parent, args, { dbName, dataSources, selectMap }) => {
      if (parent.parties_iri === undefined) return null;
      const reducer = getCommonReducer('PARTY');
      const edges = [];
      const sparqlQuery = selectAllParties(selectMap.getNode('node'), args, parent);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select All Parties',
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

      let filterCount;
      let resultCount;
      let limit;
      let offset;
      let limitSize;
      let offsetSize;
      limitSize = limit = args.first === undefined ? response.length : args.first;
      offsetSize = offset = args.offset === undefined ? 0 : args.offset;
      filterCount = 0;
      let partyList;
      if (args.orderedBy !== undefined) {
        partyList = response.sort(compareValues(args.orderedBy, args.orderMode));
      } else {
        partyList = response;
      }

      if (offset > partyList.length) return null;
      resultCount = partyList.length;
      for (const party of partyList) {
        if (offset) {
          offset--;
          continue;
        }

        // if props were requested
        if (selectMap.getNode('node').includes('props')) {
          const props = convertToProperties(party, partyPredicateMap);
          if (props !== undefined) party.props = props;
        }

        // filter out non-matching entries if a filter is to be applied
        if ('filters' in args && args.filters != null && args.filters.length > 0) {
          if (!filterValues(party, args.filters, args.filterMode)) {
            continue;
          }
          filterCount++;
        }
        // if haven't reached limit to be returned
        if (limit) {
          const edge = {
            cursor: party.iri,
            node: reducer(party),
          };
          edges.push(edge);
          limit--;
          if (limit === 0) break;
        }
      }

      // check if there is data to be returned
      if (edges.length === 0) return null;
      let hasNextPage = false;
      let hasPreviousPage = false;
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
    },
    responsible_parties: async (parent, args, { dbName, dataSources, selectMap }) => {
      if (parent.responsible_parties_iri === undefined) return null;
      const reducer = getCommonReducer('RESPONSIBLE-PARTY');
      const edges = [];
      const sparqlQuery = selectAllResponsibleParties(selectMap.getNode('node'), args, parent);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select All Responsible Parties',
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

      let filterCount;
      let resultCount;
      let limit;
      let offset;
      let limitSize;
      let offsetSize;
      limitSize = limit = args.first === undefined ? response.length : args.first;
      offsetSize = offset = args.offset === undefined ? 0 : args.offset;
      filterCount = 0;
      let itemList;
      if (args.orderedBy !== undefined) {
        itemList = response.sort(compareValues(args.orderedBy, args.orderMode));
      } else {
        itemList = response;
      }

      if (offset > itemList.length) return null;
      resultCount = itemList.length;
      for (const item of itemList) {
        if (offset) {
          offset--;
          continue;
        }

        // if props were requested
        if (selectMap.getNode('node').includes('props')) {
          const props = convertToProperties(item, responsiblePartyPredicateMap);
          if (props !== null) item.props = props;
        }

        // filter out non-matching entries if a filter is to be applied
        if ('filters' in args && args.filters != null && args.filters.length > 0) {
          if (!filterValues(item, args.filters, args.filterMode)) {
            continue;
          }
          filterCount++;
        }
        // if haven't reached limit to be returned
        if (limit) {
          const edge = {
            cursor: item.iri,
            node: reducer(item),
          };
          edges.push(edge);
          limit--;
          if (limit === 0) break;
        }
      }

      // check if there is data to be returned
      if (edges.length === 0) return null;
      let hasNextPage = false;
      let hasPreviousPage = false;
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
    },
    local_definitions: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.local_definitions_iri === undefined) return null;
      const iri = Array.isArray(parent.local_definitions_iri)
        ? parent.local_definitions_iri[0]
        : parent.local_definitions_iri;
      const reducer = getReducer('POAM-LOCAL-DEFINITION');
      const sparqlQuery = selectPOAMLocalDefinitionByIriQuery(iri, selectMap.getNode('local_definitions'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select POAM Local definitions',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      if (response === undefined || (Array.isArray(response) && response.length === 0)) {
        console.error(`[CYIO] NON-EXISTENT: (${dbName}) '${iri}'; skipping entity`);
        return null;
      }
      return reducer(response[0]);
    },
    observations: async (parent, args, { dbName, dataSources, selectMap }) => {
      if (parent.observations_iri === undefined) return null;
      const edges = [];
      const reducer = getAssessmentReducer('OBSERVATION');
      const sparqlQuery = selectAllObservations(selectMap.getNode('node'), args, parent);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: 'Select Referenced Observations',
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

      let filterCount;
      let resultCount;
      let limit;
      let offset;
      let limitSize;
      let offsetSize;
      limitSize = limit = args.first === undefined ? response.length : args.first;
      offsetSize = offset = args.offset === undefined ? 0 : args.offset;
      filterCount = 0;
      let observationList;
      if (args.orderedBy !== undefined) {
        observationList = response.sort(compareValues(args.orderedBy, args.orderMode));
      } else {
        observationList = response;
      }

      if (offset > observationList.length) return null;
      for (const observation of observationList) {
        if (offset) {
          offset--;
          continue;
        }

        // filter out non-matching entries if a filter is to be applied
        if ('filters' in args && args.filters != null && args.filters.length > 0) {
          if (!filterValues(observation, args.filters, args.filterMode)) {
            continue;
          }
          filterCount++;
        }
        // if haven't reached limit to be returned
        if (limit) {
          const edge = {
            cursor: observation.iri,
            node: reducer(observation),
          };
          edges.push(edge);
          limit--;
          if (limit === 0) break;
        }
      }

      // check if there is data to be returned
      if (edges.length === 0) return null;
      let hasNextPage = false;
      let hasPreviousPage = false;
      resultCount = observationList.length;
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
    },
    risks: async (parent, args, { dbName, dataSources, selectMap }) => {
      if (parent.risks_iri === undefined) return null;
      const edges = [];
      let filterCount;
      let resultCount;
      let limit;
      let offset;
      let limitSize;
      let offsetSize;
      filterCount = 0;
      const reducer = getAssessmentReducer('RISK');
      const sparqlQuery = selectAllRisks(selectMap.getNode('node'), args, parent);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select Referenced Risks',
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

      limitSize = limit = args.first === undefined ? response.length : args.first;
      offsetSize = offset = args.offset === undefined ? 0 : args.offset;
      resultCount = response.length;

      // update the risk level and score before sorting
      for (const risk of response) {
        risk.risk_level = 'unknown';
        if (risk.cvssV2Base_score !== undefined || risk.cvssV3Base_score !== undefined) {
          // calculate the risk level
          const { riskLevel, riskScore } = calculateRiskLevel(risk);
          risk.risk_score = riskScore;
          risk.risk_level = riskLevel;

          // clean up
          delete risk.cvssV2Base_score;
          delete risk.cvssV2Temporal_score;
          delete risk.cvssV3Base_score;
          delete risk.cvssV3Temporal_score;
          delete risk.available_exploit_values;
          delete risk.exploitability_ease_values;
        }

        // retrieve most recent remediation state
        if (risk.remediation_type_values !== undefined) {
          const { responseType, lifeCycle } = getLatestRemediationInfo(risk);
          if (responseType !== undefined) risk.response_type = responseType;
          if (lifeCycle !== undefined) risk.lifecycle = lifeCycle;
          // clean up
          delete risk.remediation_type_values;
          delete risk.remediation_lifecycle_values;
          delete risk.remediation_timestamp_values;
        }

        // TODO: WORKAROUND fix up invalidate deviation values
        if (risk.risk_status == 'deviation_requested' || risk.risk_status == 'deviation_approved') {
          console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${risk.iri} invalid field value 'risk_status'; fixing`);
          risk.risk_status = risk.risk_status.replace('_', '-');
        }
        // END WORKAROUND
      }

      // sort the values
      let riskList;
      let sortBy;
      if (args.orderedBy !== undefined) {
        if (args.orderedBy === 'risk_level') {
          sortBy = 'risk_score';
        } else {
          sortBy = args.orderedBy;
        }
        riskList = response.sort(compareValues(sortBy, args.orderMode));
      } else {
        riskList = response;
      }

      if (offset > riskList.length) return null;
      // for each Risk in the result set
      for (const risk of riskList) {
        if (risk.id === undefined || risk.id == null) {
          console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${risk.iri} missing field 'id'; skipping`);
          continue;
        }

        // skip down past the offset
        if (offset) {
          offset--;
          continue;
        }

        // Provide default values if missing - MUST be done before converting to props
        if (!('false_positive' in risk)) risk.false_positive = false;
        if (!('accepted' in risk)) risk.accepted = false;
        if (!('risk_adjusted' in risk)) risk.risk_adjusted = false;
        if (!('vendor_dependency' in risk)) risk.vendor_dependency = false;

        // if props were requested
        if (selectMap.getNode('node').includes('props')) {
          let props = convertToProperties(risk, riskPredicateMap);
          if (risk.hasOwnProperty('risk_level')) {
            if (props === null) props = [];
            const id_material = { name: 'risk-level', ns: 'http://darklight.ai/ns/oscal', value: `${risk.risk_level}` };
            const propId = generateId(id_material, OSCAL_NS);
            const property = {
              id: `${propId}`,
              entity_type: 'property',
              prop_name: 'risk-level',
              ns: 'http://darklight.ai/ns/oscal',
              value: `${risk.risk_level}`,
            };
            props.push(property);
          }
          if (risk.hasOwnProperty('risk_score')) {
            if (props === null) props = [];
            const id_material = { name: 'risk-score', ns: 'http://darklight.ai/ns/oscal', value: `${risk.risk_score}` };
            const propId = generateId(id_material, OSCAL_NS);
            const property = {
              id: `${propId}`,
              entity_type: 'property',
              prop_name: 'risk-score',
              ns: 'http://darklight.ai/ns/oscal',
              value: `${risk.risk_score}`,
            };
            props.push(property);
          }
          if (risk.hasOwnProperty('occurrences')) {
            if (props === null) props = [];
            const id_material = {
              name: 'risk-occurrences',
              ns: 'http://darklight.ai/ns/oscal',
              value: `${risk.occurrences}`,
            };
            const propId = generateId(id_material, OSCAL_NS);
            const property = {
              id: `${propId}`,
              entity_type: 'property',
              prop_name: 'risk-occurrences',
              ns: 'http://darklight.ai/ns/oscal',
              value: `${risk.occurrences}`,
            };
            props.push(property);
          }
          if (props !== null) risk.props = props;
        }

        // filter out non-matching entries if a filter is to be applied
        if ('filters' in args && args.filters != null && args.filters.length > 0 && args.filters[0] !== null) {
          if (!filterValues(risk, args.filters, args.filterMode)) {
            continue;
          }
          filterCount++;
        }

        // if haven't reached limit to be returned
        if (limit) {
          const edge = {
            cursor: risk.iri,
            node: reducer(risk),
          };
          edges.push(edge);
          limit--;
          if (limit === 0) break;
        }
      }

      // check if there is data to be returned
      if (edges.length === 0) return null;
      let hasNextPage = false;
      let hasPreviousPage = false;
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
    },
    poam_items: async (parent, args, { dbName, dataSources, selectMap }) => {
      if (parent.poam_items_iri === undefined) return null;
      const edges = [];
      const reducer = getReducer('POAM-ITEM');
      const sparqlQuery = selectAllPOAMItems(selectMap.getNode('node'), args, parent);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select All POAM Items',
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

      let filterCount;
      let resultCount;
      let limit;
      let offset;
      let limitSize;
      let offsetSize;
      limitSize = limit = args.first === undefined ? response.length : args.first;
      offsetSize = offset = args.offset === undefined ? 0 : args.offset;
      filterCount = 0;
      let poamItemList;
      if (args.orderedBy !== undefined) {
        poamItemList = response.sort(compareValues(args.orderedBy, args.orderMode));
      } else {
        poamItemList = response;
      }

      if (offset > poamItemList.length) return null;
      for (const poamItem of poamItemList) {
        if (offset) {
          offset--;
          continue;
        }

        // if props were requested
        if (selectMap.getNode('node').includes('props') && poamItem.hasOwnProperty('poam_id')) {
          const id_material = { name: 'POAM-ID', ns: 'http://fedramp.gov/ns/oscal', value: `${poamItem.poam_id}` };
          const id = generateId(id_material, OSCAL_NS);
          const prop = {
            id: `${id}`,
            entity_type: 'property',
            prop_name: 'POAM-ID',
            ns: 'http://fedramp.gov/ns/oscal',
            value: `${poamItem.poam_id}`,
          };
          poamItem.props = [prop];
        }

        // filter out non-matching entries if a filter is to be applied
        if ('filters' in args && args.filters != null && args.filters.length > 0) {
          if (!filterValues(poamItem, args.filters, args.filterMode)) {
            continue;
          }
          filterCount++;
        }
        // if haven't reached limit to be returned
        if (limit) {
          const edge = {
            cursor: poamItem.iri,
            node: reducer(poamItem),
          };
          edges.push(edge);
          limit--;
          if (limit === 0) break;
        }
      }

      // check if there is data to be returned
      if (edges.length === 0) return null;
      let hasNextPage = false;
      let hasPreviousPage = false;
      resultCount = poamItemList.length;
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
    },
    resources: async (_parent, _args, { _dbName, _dataSources, _selectMap }) => {
      // TODO: Add implementation resource retrieval
    },
  },
  POAMLocalDefinitions: {
    components: async (_parent, args, { dbName, dataSources, selectMap }) => {
      const edges = [];
      const sparqlQuery = selectAllComponents(selectMap.getNode('node'));
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: 'Select Component List',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      // no components found
      if (response === undefined || response.length === 0) return null;

      // Handle reporting Stardog Error
      if (typeof response === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      }

      let filterCount;
      let resultCount;
      let limit;
      let offset;
      let limitSize;
      let offsetSize;
      limitSize = limit = args.first === undefined ? response.length : args.first;
      offsetSize = offset = args.offset === undefined ? 0 : args.offset;
      filterCount = 0;

      // compose name to include version and patch level
      for (const component of response) {
        // filter out network assets
        if (component.asset_type === 'network') continue;
        let { name } = component;
        if (component.hasOwnProperty('vendor_name')) {
          if (!component.name.startsWith(component.vendor_name)) name = `${component.vendor_name} ${component.name}`;
        }
        if (component.hasOwnProperty('version')) name = `${name} ${component.version}`;
        if (component.hasOwnProperty('patch_level')) name = `$${name} ${component.patch_level}`;
        component.name = name;
      }

      let componentList;
      if (args.orderedBy !== undefined) {
        componentList = response.sort(compareValues(args.orderedBy, args.orderMode));
      } else {
        componentList = response;
      }

      if (offset > componentList.length) return null;
      resultCount = componentList.length;
      for (let component of componentList) {
        if (offset) {
          offset--;
          continue;
        }

        // Determine the proper component type for the asset
        if (component.component_type === undefined) {
          switch (component.asset_type) {
            case 'software':
            case 'operating-system':
            case 'application-software':
              component.component_type = 'software';
              break;
            case 'firewall':
              component.component_type = 'software';
              break;
            case 'network':
              component.component_type = 'network';
              break;
            default:
              console.error(
                `[CYIO] UNKNOWN-COMPONENT Unknown component type '${component.component_type}' for object ${component.iri}`
              );
              console.error(
                `[CYIO] UNKNOWN-TYPE Unknown asset type '${component.asset_type}' for object ${component.iri}`
              );
              if (component.iri.includes('Software')) item.component_type = 'software';
              if (component.iri.includes('Network')) item.component_type = 'network';
              if (component.component_type === undefined) continue;
          }
        }

        // TODO: WORKAROUND missing component type
        if (!component.hasOwnProperty('operational_status')) {
          console.warn(
            `[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${component.iri} missing field 'operational_status'; fixing`
          );
          component.operational_status = 'operational';
        }
        // END WORKAROUND

        // filter out non-matching entries if a filter is to be applied
        if ('filters' in args && args.filters != null && args.filters.length > 0) {
          if (!filterValues(component, args.filters, args.filterMode)) {
            continue;
          }
          filterCount++;
        }

        // convert the asset into a component
        component = convertAssetToComponent(component);

        // if haven't reached limit to be returned
        if (limit) {
          const edge = {
            cursor: component.iri,
            node: component,
          };
          edges.push(edge);
          limit--;
          if (limit === 0) break;
        }
      }

      // check if there is data to be returned
      if (edges.length === 0) return null;
      let hasNextPage = false;
      let hasPreviousPage = false;
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
    },
    inventory_items: async (_parent, args, { dbName, dataSources, selectMap }) => {
      const edges = [];
      const sparqlQuery = selectAllInventoryItems(selectMap.getNode('node'), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: 'Select Inventory Item List',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      // no Inventory Items found
      if (response === undefined || response.length === 0) return null;

      // Handle reporting Stardog Error
      if (typeof response === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      }

      let filterCount;
      let resultCount;
      let limit;
      let offset;
      let limitSize;
      let offsetSize;
      limitSize = limit = args.first === undefined ? response.length : args.first;
      offsetSize = offset = args.offset === undefined ? 0 : args.offset;
      filterCount = 0;
      let inventoryItemList;
      if (args.orderedBy !== undefined) {
        inventoryItemList = response.sort(compareValues(args.orderedBy, args.orderMode));
      } else {
        inventoryItemList = response;
      }

      if (offset > inventoryItemList.length) return null;
      resultCount = inventoryItemList.length;
      for (let inventoryItem of inventoryItemList) {
        if (offset) {
          offset--;
          continue;
        }

        // filter out non-matching entries if a filter is to be applied
        if ('filters' in args && args.filters != null && args.filters.length > 0) {
          if (!filterValues(inventoryItem, args.filters, args.filterMode)) {
            continue;
          }
          filterCount++;
        }

        // convert the asset into a component
        inventoryItem = convertAssetToInventoryItem(inventoryItem);

        // if haven't reached limit to be returned
        if (limit) {
          const edge = {
            cursor: inventoryItem.iri,
            node: inventoryItem,
          };
          edges.push(edge);
          limit--;
          if (limit === 0) break;
        }
      }

      // check if there is data to be returned
      if (edges.length === 0) return null;
      let hasNextPage = false;
      let hasPreviousPage = false;
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
    },
    assessment_assets: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.assessment_assets_iri === undefined) return null;
      const iri = parent.assessment_assets_iri[0];
      const reducer = getAssessmentReducer('ASSESSMENT-ASSET');
      const sparqlQuery = selectAssessmentAssetByIriQuery(iri, selectMap.getNode('assessment_assets'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select Assessment Asset',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      if (response === undefined || (Array.isArray(response) && response.length === 0)) {
        console.error(`[CYIO] NON-EXISTENT: (${dbName}) '${iri}'; skipping entity`);
        return null;
      }

      // Handle reporting Stardog Error
      if (typeof response === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      }

      return reducer(response[0]);
    },
  },
};

export default poamResolvers;
