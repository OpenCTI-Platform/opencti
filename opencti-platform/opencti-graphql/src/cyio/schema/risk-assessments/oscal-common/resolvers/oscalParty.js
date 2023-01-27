import { UserInputError } from 'apollo-server-express';
import { riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import { compareValues, updateQuery, filterValues, CyioError } from '../../../utils.js';
import { convertToProperties } from '../../riskUtils.js';
import {
  selectLabelByIriQuery,
  selectExternalReferenceByIriQuery,
  selectNoteByIriQuery,
  selectAddressByIriQuery,
  selectPhoneNumberByIriQuery,
  deleteAddressByIriQuery,
  deletePhoneNumberByIriQuery,
  insertAddressesQuery,
  insertPhoneNumbersQuery,
  getReducer as getGlobalReducer,
} from '../../../global/resolvers/sparql-query.js';
import {
  getReducer,
  insertPartyQuery,
  selectPartyQuery,
  selectPartyByIriQuery,
  selectAllParties,
  deletePartyQuery,
  attachToPartyQuery,
  detachFromPartyQuery,
  partyPredicateMap,
  selectLocationByIriQuery,
  insertExternalIdentifiersQuery,
  selectExternalIdentifierByIriQuery,
  getReducer as getCommonReducer,
} from './sparql-query.js';
import { attachToPOAMQuery, detachFromPOAMQuery } from '../../poam/resolvers/sparql-query.js';

const oscalPartyResolvers = {
  Query: {
    oscalParties: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllParties(selectMap.getNode('node'), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: 'Select Party List',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined || response.length === 0) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer('PARTY');
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

        // for each Role in the result set
        for (const party of partyList) {
          // skip down past the offset
          if (offset) {
            offset--;
            continue;
          }

          if (party.id === undefined || party.id == null) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${party.iri} missing field 'id'; skipping`);
            continue;
          }

          // if props were requested
          if (selectMap.getNode('node').includes('props')) {
            const props = convertToProperties(party, partyPredicateMap);
            if (props !== null) party.props = props;
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
        resultCount = partyList.length;
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
    oscalParty: async (_, { id }, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectPartyQuery(id, selectMap.getNode('oscalParty'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select OSCAL Party',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const party = response[0];

        // if props were requested
        if (selectMap.getNode('oscalParty').includes('props')) {
          const props = convertToProperties(party, partyPredicateMap);
          if (props !== null) party.props = props;
        }

        const reducer = getReducer('PARTY');
        return reducer(party);
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
    createOscalParty: async (_, { input }, { dbName, selectMap, dataSources }) => {
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
      let addresses;
      let phoneNumbers;
      let memberOrgs;
      let locations;
      let externalIds;
      if (input.telephone_numbers !== undefined) {
        phoneNumbers = input.telephone_numbers;
        delete input.telephone_numbers;
      }
      if (input.addresses !== undefined) {
        addresses = input.addresses;
        delete input.addresses;
      }
      if (input.external_identifiers !== undefined) {
        externalIds = input.external_identifiers;
        delete input.external_identifiers;
      }
      if (input.member_of_organizations !== undefined) {
        memberOrgs = input.member_of_organizations;
        delete input.member_of_organizations;
      }
      if (input.locations !== undefined) {
        locations = input.locations;
        delete input.locations;
      }

      // create the Party
      const { iri, id, query } = insertPartyQuery(input);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: query,
        queryId: 'Create OSCAL Party',
      });

      // add the Party to the parent object (if supplied)
      // TODO: WORKAROUND attach the party to the default POAM until Metadata object is supported
      const poamId = '22f2ad37-4f07-5182-bf4e-59ea197a73dc';
      const attachQuery = attachToPOAMQuery(poamId, 'parties', iri);
      try {
        await dataSources.Stardog.create({
          dbName,
          queryId: 'Add Party to POAM',
          sparqlQuery: attachQuery,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      // END WORKAROUND

      // create any address supplied and attach them to the Party
      if (addresses !== undefined && addresses !== null) {
        // create the address
        const { addrIris, query } = insertAddressesQuery(addresses);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: 'Create address of Party',
        });
        // attach the address to the Party
        const addrAttachQuery = attachToPartyQuery(id, 'addresses', addrIris);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: addrAttachQuery,
          queryId: 'Attach address to Party',
        });
      }

      // create any external identifiers supplied and attach them to the Party
      if (externalIds !== undefined && externalIds !== null) {
        // create the External Identifier
        const { extIdIris, query } = insertExternalIdentifiersQuery(externalIds);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: 'Create External Identifiers of Party',
        });
        // attach the address to the Party
        const extIdAttachQuery = attachToPartyQuery(id, 'external_identifiers', extIdIris);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: extIdAttachQuery,
          queryId: 'Attach External Identifier to Party',
        });
      }

      // create any telephone numbers supplied and attach them to the Party
      if (phoneNumbers !== undefined && phoneNumbers !== null) {
        // create the Telephone Number
        const { phoneIris, query } = insertPhoneNumbersQuery(phoneNumbers);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: 'Create telephone numbers of Party',
        });
        // attach the address to the Party
        const phoneAttachQuery = attachToPartyQuery(id, 'telephone_numbers', phoneIris);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: phoneAttachQuery,
          queryId: 'Attach telephone numbers to Party',
        });
      }
      // create any members supplied and attach them to the Party
      if (memberOrgs !== undefined && memberOrgs !== null) {
        const partyIris = [];
        for (const partyId of memberOrgs) partyIris.push(`<http://csrc.nist.gov/ns/oscal/common#Party-${partyId}>`);

        // attach the reference of a Party to this Party
        const partyAttachQuery = attachToPartyQuery(id, 'member_of_organization', partyIris);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: partyAttachQuery,
          queryId: 'Attach reference to a Party to this Party',
        });
      }
      // create any locations supplied and attach them to the Party
      if (locations !== undefined && locations !== null) {
        const locationIris = [];
        for (const locationId of locations)
          locationIris.push(`<http://csrc.nist.gov/ns/oscal/common#Location-${locationId}>`);

        // attach the reference of a Party to this Party
        const partyAttachQuery = attachToPartyQuery(id, 'locations', locationIris);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: partyAttachQuery,
          queryId: 'Attach reference to a Location to this Party',
        });
      }

      // retrieve information about the newly created Party to return to the user
      const select = selectPartyQuery(id, selectMap.getNode('createOscalParty'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: 'Select OSCAL Party',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      const reducer = getReducer('PARTY');
      return reducer(response[0]);
    },
    deleteOscalParty: async (_, { id }, { dbName, dataSources }) => {
      // check that the Party exists
      const sparqlQuery = selectPartyQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select OSCAL Party',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);
      const reducer = getReducer('PARTY');
      const party = reducer(response[0]);

      // detach the Party from the parent object (if supplied)
      // TODO: WORKAROUND attach the party to the default POAM until Metadata object is supported
      const poamId = '22f2ad37-4f07-5182-bf4e-59ea197a73dc';
      const detachQuery = detachFromPOAMQuery(poamId, 'parties', party.iri);
      try {
        await dataSources.Stardog.create({
          dbName,
          queryId: 'Detaching Party from POAM',
          sparqlQuery: detachQuery,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      // END WORKAROUND

      // TODO: Determine any external attachments that will need to be removed when this object is deleted

      // Delete any attached addresses
      if (party.hasOwnProperty('addresses_iri')) {
        for (const addrIri of party.addresses_iri) {
          const addrQuery = deleteAddressByIriQuery(addrIri);
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: addrQuery,
            queryId: 'Delete Address from this Party',
          });
        }
      }
      // Delete any attached External Identifiers
      if (party.hasOwnProperty('external_identifiers_iri')) {
        for (const extIdIri of party.external_identifiers_iri) {
          const extIdQuery = deleteExternalIdentifierByIriQuery(extIdIri);
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: extIdQuery,
            queryId: 'Delete External Identifier from this Party',
          });
        }
      }
      // Delete any attached telephone numbers
      if (party.hasOwnProperty('telephone_numbers_iri')) {
        for (const phoneIri of party.telephone_numbers_iri) {
          const phoneQuery = deletePhoneNumberByIriQuery(phoneIri);
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: phoneQuery,
            queryId: 'Delete Telephone Number from this Party',
          });
        }
      }
      // Detach any parties that this party is associated with
      if (party.hasOwnProperty('member_of_organizations_iri')) {
        for (const partyIri of party.member_of_organizations_iri) {
          const partyQuery = detachFromPartyQuery(id, 'member_of_organizations', partyIri);
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: partyQuery,
            queryId: 'Delete association with Party from this Party',
          });
        }
      }
      // Detach any locations that this party is associated with
      if (party.hasOwnProperty('locations_iri')) {
        for (const locationIri of party.locations_iri) {
          const locationQuery = detachFromPartyQuery(id, 'locations', locationIri);
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: locationQuery,
            queryId: 'Delete association with Location from this Party',
          });
        }
      }

      // Delete the Party itself
      const query = deletePartyQuery(id);
      try {
        await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: 'Delete OSCAL Party',
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      return id;
    },
    editOscalParty: async (_, { id, input }, { dbName, dataSources, selectMap }) => {
      // make sure there is input data containing what is to be edited
      if (input === undefined || input.length === 0) throw new CyioError(`No input data was supplied`);

      // TODO: WORKAROUND to remove immutable fields
      input = input.filter(
        (element) => element.key !== 'id' && element.key !== 'created' && element.key !== 'modified'
      );

      // check that the object to be edited exists with the predicates - only get the minimum of data
      const editSelect = ['id', 'created', 'modified', 'party_type'];
      for (const editItem of input) {
        editSelect.push(editItem.key);
      }
      const sparqlQuery = selectPartyQuery(id, editSelect);
      const response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: 'Select OSCAL Party',
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

      const reducer = getReducer('PARTY');
      const party = reducer(response[0]);

      // determine the appropriate ontology class type
      if (!party.hasOwnProperty('party_type')) throw new CyioError(`Unknown type of party with ID ${id}`);
      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/common#Party-${id}`,
        `http://csrc.nist.gov/ns/oscal/common#Party`,
        input,
        partyPredicateMap
      );
      if (query !== null) {
        let response;
        try {
          response = await dataSources.Stardog.edit({
            dbName,
            sparqlQuery: query,
            queryId: 'Update OSCAL Party',
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

      const select = selectPartyQuery(id, selectMap.getNode('editOscalParty'));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: 'Select OSCAL Party',
        singularizeSchema,
      });
      return reducer(result[0]);
    },
  },
  OscalParty: {
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
    addresses: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.addresses_iri === undefined) return [];
      const iriArray = parent.addresses_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer('ADDRESS');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Address')) continue;
          const sparqlQuery = selectAddressByIriQuery(iri, selectMap.getNode('addresses'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Address',
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
    member_of_organizations: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.member_of_organizations_iri === undefined) return [];
      const iriArray = parent.member_of_organizations_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer('PARTY');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Party')) continue;
          const sparqlQuery = selectPartyByIriQuery(iri, selectMap.getNode('member_of_organizations'));
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
    locations: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.locations_iri === undefined) return [];
      const iriArray = parent.locations_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getCommonReducer('LOCATION');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Location')) continue;
          const sparqlQuery = selectLocationByIriQuery(iri, selectMap.getNode('locations'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Location',
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
    telephone_numbers: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.telephone_numbers_iri === undefined) return [];
      const iriArray = parent.telephone_numbers_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer('PHONE-NUMBER');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('TelephoneNumber')) continue;
          const sparqlQuery = selectPhoneNumberByIriQuery(iri, selectMap.getNode('telephone_numbers'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Telephone number',
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
    external_identifiers: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.external_identifiers_iri === undefined) return [];
      const iriArray = parent.external_identifiers_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer('EXTERNAL-IDENTIFIER');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('ExternalIdentifier')) continue;
          const sparqlQuery = selectExternalIdentifierByIriQuery(iri, selectMap.getNode('external_identifiers'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select External  Identifier',
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
    email_addresses: async (parent, _) => {
      // this is necessary to work around an issue were an array a strings is returned as a single value.
      if (parent.email_addresses === undefined) return [];
      const results = [];
      const emailAddresses = parent.email_addresses[0].split(',');
      for (const emailAddress of emailAddresses) {
        results.push(emailAddress);
      }
      return results;
    },
  },
};

export default oscalPartyResolvers;
