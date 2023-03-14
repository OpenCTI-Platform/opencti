import { UserInputError } from 'apollo-server-errors';
import { globalSingularizeSchema as singularizeSchema } from '../global-mappings.js';
import { compareValues, filterValues, checkIfValidUUID } from '../../utils.js';
import { objectMap } from '../global-utils.js';
import {
  getReducer,
  selectAddressQuery,
  selectAllAddresses,
  selectAllPhoneNumbers,
  selectPhoneNumberQuery,
} from './sparql-query.js';

const cyioGlobalTypeResolvers = {
  Query: {
    civicAddresses: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllAddresses(selectMap.getNode('node'), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: 'Select Address List',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer('ADDRESS');
        let filterCount;
        let resultCount;
        let limit;
        let offset;
        let limitSize;
        let offsetSize;
        limitSize = limit = args.first === undefined ? response.length : args.first;
        offsetSize = offset = args.offset === undefined ? 0 : args.offset;
        filterCount = 0;
        let addrList;
        if (args.orderedBy !== undefined) {
          addrList = response.sort(compareValues(args.orderedBy, args.orderMode));
        } else {
          addrList = response;
        }

        if (offset > addrList.length) return null;

        // for each Role in the result set
        for (const addr of addrList) {
          // skip down past the offset
          if (offset) {
            offset--;
            continue;
          }

          if (addr.id === undefined || addr.id == null) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${addr.iri} missing field 'id'; skipping`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(addr, args.filters, args.filterMode)) {
              continue;
            }
            filterCount++;
          }

          // if haven't reached limit to be returned
          if (limit) {
            const edge = {
              cursor: addr.iri,
              node: reducer(addr),
            };
            edges.push(edge);
            limit--;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0) return null;
        let hasNextPage = false;
        let hasPreviousPage = false;
        resultCount = addrList.length;
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
    civicAddress: async (_, { id }, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAddressQuery(id, selectMap.getNode('civicAddress'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select OSCAL Civic Address',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer('ADDRESS');
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
    telephoneNumbers: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllPhoneNumbers(selectMap.getNode('node'), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: 'Select Telephone Number List',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer('PHONE-NUMBER');
        let filterCount;
        let resultCount;
        let limit;
        let offset;
        let limitSize;
        let offsetSize;
        limitSize = limit = args.first === undefined ? response.length : args.first;
        offsetSize = offset = args.offset === undefined ? 0 : args.offset;
        filterCount = 0;
        let phoneList;
        if (args.orderedBy !== undefined) {
          phoneList = response.sort(compareValues(args.orderedBy, args.orderMode));
        } else {
          phoneList = response;
        }

        if (offset > phoneList.length) return null;

        // for each Role in the result set
        for (const phoneNumber of phoneList) {
          // skip down past the offset
          if (offset) {
            offset--;
            continue;
          }

          if (phoneNumber.id === undefined || phoneNumber.id == null) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${phoneNumber.iri} missing field 'id'; skipping`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(phoneNumber, args.filters, args.filterMode)) {
              continue;
            }
            filterCount++;
          }

          // if haven't reached limit to be returned
          if (limit) {
            const edge = {
              cursor: phoneNumber.iri,
              node: reducer(phoneNumber),
            };
            edges.push(edge);
            limit--;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0) return null;
        let hasNextPage = false;
        let hasPreviousPage = false;
        resultCount = phoneList.length;
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
    telephoneNumber: async (_, { id }, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectPhoneNumberQuery(id, selectMap.getNode('telephoneNumber'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select OSCAL Telephone Number',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer('PHONE-NUMBER');
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
    addReference: async (_, { input }, { dbName, dataSources }) => {
      // if the types are not supplied, just return false - this will be removed when the field are required
      if (input.from_type === undefined || input.to_type === undefined)
        throw new UserInputError(`Source and target types must be supplied`);

      if (!checkIfValidUUID(input.from_id)) throw new UserInputError(`Invalid identifier: ${input.from_id}`);
      if (!checkIfValidUUID(input.to_id)) throw new UserInputError(`Invalid identifier: ${input.to_id}`);
      
      // Validate source (from) and target (to) are valid types
      if (!objectMap.hasOwnProperty(input.from_type)) {
        let found = false;
        for (const [key, value] of Object.entries(objectMap)) {
          // check for alternate key
          if (value.alternateKey != undefined && input.from_type == value.alternateKey) {
            input.from_type = key;
            found = true;
            break;
          }
          // check if the GraphQL type name was supplied
          if (input.from_type == value.graphQLType) {
            input.from_type = key;
            found = true;
            break;
          }
        }
        if (!found) throw new UserInputError(`Unknown source type '${input.from_type}'`);
      }
      if (!objectMap.hasOwnProperty(input.to_type)) {
        let found = false;
        for (const [key, value] of Object.entries(objectMap)) {
          // check for alternate key
          if (value.alternateKey != undefined && input.to_type == value.alternateKey) {
            input.to_type = key;
            found = true;
            break;
          }
          // check if the GraphQL type name was supplied
          if (input.to_type == value.graphQLType) {
            input.to_type = key;
            found = true;
            break;
          }
        }
        if (!found) throw new UserInputError(`Unknown source type '${input.to_type}'`);
      }

      // Validate field is defined on the source (from)
      const { predicateMap } = objectMap[input.from_type];
      if (!predicateMap.hasOwnProperty(input.field_name))
        throw new UserInputError(`Field '${input.field_name}' is not defined for the source entity.`);
      const { predicate } = predicateMap[input.field_name];

      // construct the IRIs for source (from) and target (to)
      let { from_type } = input;
      while (objectMap[from_type].parent !== undefined) {
        from_type = objectMap[from_type].parent;
      }
      let { to_type } = input;
      while (objectMap[to_type].parent !== undefined) {
        to_type = objectMap[to_type].parent;
      }
      const sourceIri = `<${objectMap[from_type].iriTemplate}-${input.from_id}>`;
      const targetIri = `<${objectMap[to_type].iriTemplate}-${input.to_id}>`;

      const query = `
      INSERT DATA {
        GRAPH ${sourceIri} {
          ${sourceIri} ${predicate} ${targetIri} .
        }
      }
      `;
      let response;
      try {
        response = await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: 'Create reference',
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return false;
      return true;
    },
    removeReference: async (_, { input }, { dbName, dataSources }) => {
      // if the types are not supplied, just return false - this will be removed when the field are required
      if (input.from_type === undefined || input.to_type === undefined)
        throw new UserInputError(`Source and target types must be supplied`);

      if (!checkIfValidUUID(input.from_id)) throw new UserInputError(`Invalid identifier: ${input.from_id}`);
      if (!checkIfValidUUID(input.to_id)) throw new UserInputError(`Invalid identifier: ${input.to_id}`);  

      // Validate source (from) and target (to) are valid types
      if (!objectMap.hasOwnProperty(input.from_type)) {
        let found = false;
        for (const [key, value] of Object.entries(objectMap)) {
          // check for alternate key
          if (value.alternateKey != undefined && input.from_type == value.alternateKey) {
            input.from_type = key;
            found = true;
            break;
          }
          // check if the GraphQL type name was supplied
          if (input.from_type == value.graphQLType) {
            input.from_type = key;
            found = true;
            break;
          }
        }
        if (!found) throw new UserInputError(`Unknown source type '${input.from_type}'`);
      }
      if (!objectMap.hasOwnProperty(input.to_type)) {
        let found = false;
        for (const [key, value] of Object.entries(objectMap)) {
          // check for alternate key
          if (value.alternateKey != undefined && input.to_type == value.alternateKey) {
            input.from_type = key;
            found = true;
            break;
          }
          // check if the GraphQL type name was supplied
          if (input.to_type == value.graphQLType) {
            input.to_type = key;
            found = true;
            break;
          }
        }
        if (!found) throw new UserInputError(`Unknown source type '${input.to_type}'`);
      }

      // Validate field value is defined on the source (from)
      const { predicateMap } = objectMap[input.from_type];
      if (!predicateMap.hasOwnProperty(input.field_name))
        throw new UserInputError(`Field '${input.field_name}' is not defined for the source entity.`);
      const { predicate } = predicateMap[input.field_name];

      // construct the IRIs for source (from) and target (to)
      let { from_type } = input;
      while (objectMap[from_type].parent !== undefined) {
        from_type = objectMap[from_type].parent;
      }
      let { to_type } = input;
      while (objectMap[to_type].parent !== undefined) {
        to_type = objectMap[to_type].parent;
      }
      const sourceIri = `<${objectMap[from_type].iriTemplate}-${input.from_id}>`;
      const targetIri = `<${objectMap[to_type].iriTemplate}-${input.to_id}>`;

      const query = `
      DELETE DATA {
        GRAPH ${sourceIri} {
          ${sourceIri} ${predicate} ${targetIri} .
        }
      }
      `;
      let response;
      try {
        response = await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: 'Remove reference',
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return false;
      return true;
    },
  },
  // Map enum GraphQL values to data model required values
  OperationalStatus: {
    under_development: 'under-development',
    under_major_modification: 'under-major-modifications',
  },
  CyioLocationType: {
    geo_location: 'geo-location',
    civic_address: 'civic-address',
  },
  RegionName: {
    africa: 'africa',
    eastern_africa: 'eastern-africa',
    middle_africa: 'middle-africa',
    northern_africa: 'northern-africa',
    southern_africa: 'southern-africa',
    western_africa: 'western-africa',
    americas: 'americas',
    caribbean: 'caribbean',
    central_america: 'central-america',
    latin_america_caribbean: 'latin-america-caribbean',
    northern_america: 'northern-america',
    south_america: 'south-america',
    asia: 'asia',
    central_asia: 'central-asia',
    eastern_asia: 'eastern-asia',
    southern_asia: 'southern-asia',
    south_eastern_asia: 'south-eastern-asia',
    western_asia: 'western-asia',
    europe: 'europe',
    eastern_europe: 'eastern-europe',
    northern_europe: 'northern-europe',
    southern_europe: 'southern-europe',
    western_europe: 'western-europe',
    oceania: 'oceania',
    antarctica: 'antarctica',
    australia_new_zealand: 'australia-new-zealand',
    melanesia: 'melanesia',
    micronesia: 'micronesia',
    polynesia: 'polynesia',
  },
}

export default cyioGlobalTypeResolvers;
