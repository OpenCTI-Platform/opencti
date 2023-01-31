import { UserInputError } from 'apollo-server-express';
import { riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import { compareValues, updateQuery, filterValues, CyioError } from '../../../utils.js';
import {
  selectLabelByIriQuery,
  selectExternalReferenceByIriQuery,
  selectNoteByIriQuery,
  getReducer as getGlobalReducer,
} from '../../../global/resolvers/sparql-query.js';
import { attachToPOAMQuery, detachFromPOAMQuery } from '../../poam/resolvers/sparql-query.js';
import {
  getReducer,
  insertRoleQuery,
  selectRoleQuery,
  selectAllRoles,
  deleteRoleQuery,
  rolePredicateMap,
} from './sparql-query.js';

const oscalRoleResolvers = {
  Query: {
    oscalRoles: async (_, args, { dbName, dataSources, selectMap }) => {
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

      const sparqlQuery = selectAllRoles(selectMap.getNode('node'), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: 'Select Role List',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer('ROLE');
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

        // for each Role in the result set
        for (const role of roleList) {
          // skip down past the offset
          if (offset) {
            offset--;
            continue;
          }

          if (role.id === undefined || role.id == null) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${role.iri} missing field 'id'; skipping`);
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
        resultCount = roleList.length;
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
    oscalRole: async (_, { id }, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectRoleQuery(id, selectMap.getNode('oscalRole'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select OSCAL Role',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer('ROLE');
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
    createOscalRole: async (_, { input }, { dbName, selectMap, dataSources }) => {
      // TODO: WORKAROUND to remove input fields with null or empty values so creation will work
      for (const [key, value] of Object.entries(input)) {
        if (Array.isArray(input[key]) && input[key].length === 0) {
          delete input[key];
          continue;
        }
        if (value === null || value.length === 0) {
          delete input[key];
        }
        if (key === 'role_identifier') {
          if (value.includes(' ')) throw new CyioError(`Invalid role identifier value; must not contains spaces`);
        }
      }
      // END WORKAROUND

      // create the Role
      const { iri, id, query } = insertRoleQuery(input);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: query,
        queryId: 'Create OSCAL Role',
      });

      // add the role to the parent object (if supplied)
      // TODO: WORKAROUND attach the role to the default POAM until Metadata object is supported
      const poamId = '22f2ad37-4f07-5182-bf4e-59ea197a73dc';
      const attachQuery = attachToPOAMQuery(poamId, 'roles', iri);
      try {
        await dataSources.Stardog.create({
          dbName,
          queryId: 'Add Role to POAM',
          sparqlQuery: attachQuery,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      // END WORKAROUND

      // retrieve information about the newly created Characterization to return to the user
      const select = selectRoleQuery(id, selectMap.getNode('createOscalRole'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: 'Select OSCAL Role',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      const reducer = getReducer('ROLE');
      return reducer(response[0]);
    },
    deleteOscalRole: async (_, { id }, { dbName, dataSources }) => {
      // check that the Role exists
      const sparqlQuery = selectRoleQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select OSCAL Role',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);
      const reducer = getReducer('ROLE');
      const role = reducer(response[0]);

      // detach the Role from the parent object (if supplied)
      // TODO: WORKAROUND attach the location to the default POAM until Metadata object is supported
      const poamId = '22f2ad37-4f07-5182-bf4e-59ea197a73dc';
      const detachQuery = detachFromPOAMQuery(poamId, 'roles', role.iri);
      try {
        await dataSources.Stardog.create({
          dbName,
          queryId: 'Detaching Role from POAM',
          sparqlQuery: detachQuery,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      // END WORKAROUND

      // TODO: Determine any external attachments that will need to be removed when this object is deleted

      // Delete the characterization itself
      const query = deleteRoleQuery(id);
      try {
        await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: 'Delete OSCAL Role',
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      return id;
    },
    editOscalRole: async (_, { id, input }, { dbName, dataSources, selectMap }) => {
      // make sure there is input data containing what is to be edited
      if (input === undefined || input.length === 0) throw new CyioError(`No input data was supplied`);

      // TODO: WORKAROUND to remove immutable fields
      input = input.filter(
        (element) => element.key !== 'id' && element.key !== 'created' && element.key !== 'modified'
      );

      // check that the object to be edited exists with the predicates - only get the minimum of data
      const editSelect = ['id', 'created', 'modified'];
      for (const editItem of input) {
        if (editItem.key === 'role_identifier') {
          if (editItem.value[0].includes(' '))
            throw new CyioError(`Invalid role identifier value; must not contains spaces`);
        }
        editSelect.push(editItem.key);
      }

      const sparqlQuery = selectRoleQuery(id, editSelect);
      const response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: 'Select OSCAL Role',
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
        `http://csrc.nist.gov/ns/oscal/common#Role-${id}`,
        'http://csrc.nist.gov/ns/oscal/common#Role',
        input,
        rolePredicateMap
      );
      if (query !== null) {
        let response;
        try {
          response = await dataSources.Stardog.edit({
            dbName,
            sparqlQuery: query,
            queryId: 'Update OSCAL Role',
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

      const select = selectRoleQuery(id, selectMap.getNode('editOscalRole'));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: 'Select OSCAL Role',
        singularizeSchema,
      });
      const reducer = getReducer('ROLE');
      return reducer(result[0]);
    },
  },
  OscalRole: {
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
};

export default oscalRoleResolvers;
