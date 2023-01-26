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
  insertResponsiblePartyQuery,
  selectResponsiblePartyQuery,
  selectAllResponsibleParties,
  deleteResponsiblePartyQuery,
  attachToResponsiblePartyQuery,
  selectPartyByIriQuery,
  selectRoleByIriQuery,
  responsiblePartyPredicateMap,
} from './sparql-query.js';
import { selectObjectIriByIdQuery } from '../../../global/global-utils.js';

const responsiblePartyResolvers = {
  Query: {
    oscalResponsibleParties: async (_, args, { dbName, dataSources, selectMap }) => {
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

      const sparqlQuery = selectAllResponsibleParties(selectMap.getNode('node'), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: 'Select List of Responsible Parties',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer('RESPONSIBLE-PARTY');
        let filterCount;
        let resultCount;
        let limit;
        let offset;
        let limitSize;
        let offsetSize;
        limitSize = limit = args.first === undefined ? response.length : args.first;
        offsetSize = offset = args.offset === undefined ? 0 : args.offset;
        filterCount = 0;
        let respPartyList;
        if (args.orderedBy !== undefined) {
          respPartyList = response.sort(compareValues(args.orderedBy, args.orderMode));
        } else {
          respPartyList = response;
        }

        if (offset > respPartyList.length) return null;

        // for each Role in the result set
        for (const respParty of respPartyList) {
          // skip down past the offset
          if (offset) {
            offset--;
            continue;
          }

          if (respParty.id === undefined || respParty.id == null) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${respParty.iri} missing field 'id'; skipping`);
            continue;
          }

          // if props were requested
          if (selectMap.getNode('node').includes('props')) {
            const props = convertToProperties(respParty, responsiblePartyPredicateMap);
            if (props !== null) respParty.props = props;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(respParty, args.filters, args.filterMode)) {
              continue;
            }
            filterCount++;
          }

          // if haven't reached limit to be returned
          if (limit) {
            const edge = {
              cursor: respParty.iri,
              node: reducer(respParty),
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
        resultCount = respPartyList.length;
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
    oscalResponsibleParty: async (_, { id }, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectResponsiblePartyQuery(id, selectMap.getNode('oscalResponsibleParty'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select OSCAL Responsible Party',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer('RESPONSIBLE-PARTY');
        const respParty = response[0];

        // if props were requested
        if (selectMap.getNode('oscalResponsibleParty').includes('props')) {
          const props = convertToProperties(respParty, responsiblePartyPredicateMap);
          if (props !== null) respParty.props = props;
        }

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
    createOscalResponsibleParty: async (_, { input }, { dbName, selectMap, dataSources }) => {
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

      // Setup to handle embedded objects to be created
      let parties;
      let role;
      if (input.parties !== undefined) {
        parties = input.parties;
      }
      if (input.role !== undefined) {
        role = input.role;
      }

      // AB#5859 - Verify no other ResponsibleParty exists with the specified role
      const sparqlQuery = selectAllResponsibleParties(['id', 'role']);
      let results;
      try {
        results = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: 'Select List of Responsible Parties',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      // check if there is already a Responsible Party defined with the specified Role
      if (results !== undefined && results.length > 0) {
        for (const respParty of results) {
          if (`<${respParty.role[0]}>` === `<http://csrc.nist.gov/ns/oscal/common#Role-${role}>`) {
            throw new CyioError('Only one Responsible Party can be assigned the specified Responsibility');
          }
        }
      }

      // create the Responsible Party
      const { iri, id, query } = insertResponsiblePartyQuery(input);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: query,
        queryId: 'Create OSCAL Responsible Party',
      });

      // add the responsible party to the parent object (if supplied)
      // TODO: WORKAROUND attach the responsible party to the default POAM until Metadata object is supported
      const poamId = '22f2ad37-4f07-5182-bf4e-59ea197a73dc';
      const attachQuery = attachToPOAMQuery(poamId, 'responsible_parties', iri);
      try {
        await dataSources.Stardog.create({
          dbName,
          queryId: 'Add Responsible Party to POAM',
          sparqlQuery: attachQuery,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      // END WORKAROUND

      // attach associated Role
      if (role !== undefined && role !== null) {
        const roleIris = [];
        roleIris.push(`<http://csrc.nist.gov/ns/oscal/common#Role-${role}>`);
        // attach the Role to the Responsible Party
        const roleAttachQuery = attachToResponsiblePartyQuery(id, 'role', roleIris);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: roleAttachQuery,
          queryId: 'Attach reference to the Role to this Responsible Party',
        });
      }
      // // attach any Parties
      if (parties !== undefined && parties !== null) {
        const partyIris = [];
        for (const partyIri of parties) partyIris.push(`<http://csrc.nist.gov/ns/oscal/common#Party-${partyIri}>`);
        // attach the Party to the Responsible Party
        const partyAttachQuery = attachToResponsiblePartyQuery(id, 'parties', partyIris);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: partyAttachQuery,
          queryId: 'Attach references to one or more Parties to this Responsible Party',
        });
      }

      // retrieve information about the newly created Responsible Party to return to the user
      const select = selectResponsiblePartyQuery(id, selectMap.getNode('createOscalResponsibleParty'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: 'Select OSCAL Responsible Party',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      const reducer = getReducer('RESPONSIBLE-PARTY');
      return reducer(response[0]);
    },
    deleteOscalResponsibleParty: async (_, { id }, { dbName, dataSources }) => {
      // check that the Role exists
      const sparqlQuery = selectResponsiblePartyQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select OSCAL Responsible Party',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);
      const reducer = getReducer('RESPONSIBLE-PARTY');
      const responsibleParty = reducer(response[0]);

      // detach the Role from the parent object (if supplied)
      // TODO: WORKAROUND attach the responsible party from the default POAM until Metadata object is supported
      const poamId = '22f2ad37-4f07-5182-bf4e-59ea197a73dc';
      const detachQuery = detachFromPOAMQuery(poamId, 'responsible_parties', responsibleParty.iri);
      try {
        await dataSources.Stardog.create({
          dbName,
          queryId: 'Detaching Responsible Party from POAM',
          sparqlQuery: detachQuery,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      // END WORKAROUND

      // TODO: Determine any external attachments that will need to be removed when this object is deleted

      // Delete the responsible party itself
      const query = deleteResponsiblePartyQuery(id);
      try {
        await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: 'Delete OSCAL Responsible party',
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      return id;
    },
    editOscalResponsibleParty: async (_, { id, input }, { dbName, dataSources, selectMap }) => {
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

      const sparqlQuery = selectResponsiblePartyQuery(id, editSelect);
      const response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: 'Select Responsible Party',
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

      // obtain the IRIs for the referenced objects so that if one doesn't
      // exists we have created anything yet.  For complex objects that are
      // private to this object, remove them (if needed) and add the new instances
      for (const editItem of input) {
        let value;
        let objType;
        let objArray;
        const iris = [];
        let isId = true;
        let relationshipQuery;
        let queryDetails;
        for (value of editItem.value) {
          switch (editItem.key) {
            case 'role':
              objType = 'oscal-role';
              // skip if not attempting to be changed
              if (response[0].role[0] === `http://csrc.nist.gov/ns/oscal/common#Role-${value}`) {
                editItem.operation = 'skip';
                break;
              }
              break;
            case 'parties':
              objType = 'oscal-party';
              break;
            default:
              isId = false;
              if (response[0].hasOwnProperty(editItem.key)) {
                if (response[0][editItem.key] === value) editItem.operation = 'skip';
              } else if (editItem.operation === 'remove') {
                editItem.operation = 'skip';
              }
              break;
          }

          if (isId && editItem.operation !== 'skip') {
            const query = selectObjectIriByIdQuery(value, objType);
            const result = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery: query,
              queryId: 'Obtaining IRI for object by id',
              singularizeSchema,
            });
            if (result === undefined || result.length === 0)
              throw new CyioError(`Entity does not exist with ID ${value}`);
            iris.push(`<${result[0].iri}>`);
          }
        }

        if (editItem.key === 'role' && editItem.operation !== 'skip') {
          const sparqlQuery = selectAllResponsibleParties(['id', 'role']);
          let response;
          try {
            response = await dataSources.Stardog.queryAll({
              dbName,
              sparqlQuery,
              queryId: 'Select List of Responsible Parties',
              singularizeSchema,
            });
          } catch (e) {
            console.log(e);
            throw e;
          }
          // check if there is already a Responsible Party defined with the specified Role
          if (response !== undefined && response.length > 0) {
            for (const respParty of response) {
              if (`<${respParty.role[0]}>` === iris[0] && respParty.id !== id) {
                throw new CyioError('Only one Responsible Party can be assigned the specified Responsibility');
              }
            }
          }
        }

        // update value with array of IRIs
        if (iris.length > 0) editItem.value = iris;
      }

      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/common#ResponsibleParty-${id}`,
        'http://csrc.nist.gov/ns/oscal/common#ResponsibleParty',
        input,
        responsiblePartyPredicateMap
      );
      if (query !== null) {
        let response;
        try {
          response = await dataSources.Stardog.edit({
            dbName,
            sparqlQuery: query,
            queryId: 'Update OSCAL Responsible Party',
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

      const select = selectResponsiblePartyQuery(id, selectMap.getNode('editOscalResponsibleParty'));
      let result;
      try {
        result = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: 'Select OSCAL Responsible Party',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      const reducer = getReducer('RESPONSIBLE-PARTY');
      return reducer(result[0]);
    },
  },
  OscalResponsibleParty: {
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
    parties: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.parties_iri === undefined) return [];
      const iriArray = parent.parties_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer('PARTY');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Party')) continue;
          const sparqlQuery = selectPartyByIriQuery(iri, selectMap.getNode('parties'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Party',
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
    role: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.role_iri === undefined) return null;
      const iri = parent.role_iri[0];
      const reducer = getReducer('ROLE');
      const sparqlQuery = selectRoleByIriQuery(iri, selectMap.getNode('role'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select Role',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        return reducer(response[0]);
      }

      // Handle reporting Stardog Error
      if (typeof response === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      }

      return null;
    },
  },
};

export default responsiblePartyResolvers;
