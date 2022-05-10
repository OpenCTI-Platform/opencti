import { riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import { compareValues, updateQuery, filterValues } from '../../../utils.js';
import { UserInputError } from "apollo-server-express";
import {
  selectLabelByIriQuery,
  selectExternalReferenceByIriQuery,
  selectNoteByIriQuery,
  selectAddressByIriQuery,
  selectPhoneNumberByIriQuery,
  deleteAddressByIriQuery,
  deletePhoneNumberByIriQuery,
  insertAddressQuery,
  insertPhoneNumbersQuery,
  getReducer as getGlobalReducer,
} from '../../../global/resolvers/sparql-query.js';
import {
  getReducer,
  insertLocationQuery,
  selectLocationQuery,
  selectAllLocations,
  deleteLocationQuery,
  attachToLocationQuery,
  locationPredicateMap,
} from './sparql-query.js';


const oscalLocationResolvers = {
  Query: {
    oscalLocations: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllLocations(selectMap.getNode("node"), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Location List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer("LOCATION");
        let filterCount, resultCount, limit, offset, limitSize, offsetSize;
        limitSize = limit = (args.first === undefined ? response.length : args.first) ;
        offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
        filterCount = 0;
        let locationList;
        if (args.orderedBy !== undefined) {
          locationList = response.sort(compareValues(args.orderedBy, args.orderMode));
        } else {
          locationList = response;
        }

        if (offset > locationList.length) return null;

        // for each Role in the result set
        for (let location of locationList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (location.id === undefined || location.id == null) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${location.iri} missing field 'id'; skipping`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(location, args.filters, args.filterMode)) {
              continue
            }
            filterCount++;
          }

          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: location.iri,
              node: reducer(location),
            }
            edges.push(edge)
            limit--;
            if (limit === 0) break;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0 ) return null;
        let hasNextPage = false, hasPreviousPage = false;
        resultCount = locationList.length;
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
    oscalLocation: async (_, {id}, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectLocationQuery(id, selectMap.getNode("oscalLocation"));
      let response;
      try {
          response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select OSCAL Location",
          singularizeSchema
          });
      } catch (e) {
          console.log(e)
          throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
          const reducer = getReducer("LOCATION");
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
    },
  },
  Mutation: {
    createOscalLocation: async (_, { input }, { dbName, selectMap, dataSources }) => {
      // Setup to handle embedded objects to be created
      let address, phoneNumbers;
      if (input.telephone_numbers !== undefined) {
        phoneNumbers = input.telephone_numbers;
        delete input.telephone_numbers;
      }
      if (input.address !== undefined) {
        address = input.address
        delete input.address;
      }
      if (input.urls) {
        let urls = [];
        // convert to string form
        for (let url of input.urls) {
          urls.push(url.toString());
        }
        input.urls = urls;
      }

      // create the Location
      const { id, query } = insertLocationQuery(input);
      let results = await dataSources.Stardog.create({
        dbName,
        sparqlQuery: query,
        queryId: "Create OSCAL Location"
      });

      // add the Location to the parent object (if supplied)

      // create the address supplied and attach them to the Location
      if (address !== undefined && address !== null) {
        // create the address
        const {iri, query} = insertAddressQuery( address );
        let results = await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: "Create address of Location"
        });
        // attach the address to the Location
        const addrAttachQuery = attachToLocationQuery(id, 'address', iri);
        results = await dataSources.Stardog.create({
          dbName,
          sparqlQuery: addrAttachQuery,
          queryId: "Attach address to Location"
        });
      }
      // create any telephone numbers supplied and attach them to the Location
      if (phoneNumbers !== undefined && phoneNumbers !== null) {
        // create the Telephone Number
        const {phoneIris, query} = insertPhoneNumbersQuery( phoneNumbers );
        let results = await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: "Create telephone numbers of Location"
        });
        // attach the address to the Location
        const phoneAttachQuery = attachToLocationQuery(id, 'telephone_numbers', phoneIris);
        results = await dataSources.Stardog.create({
          dbName,
          sparqlQuery: phoneAttachQuery,
          queryId: "Attach telephone numbers to Location"
        });
      }

      // retrieve information about the newly created Location to return to the user
      const select = selectLocationQuery(id, selectMap.getNode("createOscalLocation"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: "Select OSCAL Location",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      const reducer = getReducer("LOCATION");
      return reducer(response[0]);
    },
    deleteOscalLocation: async (_, { id }, { dbName, dataSources }) => {
      // check that the Party exists
      const sparqlQuery = selectLocationQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select OSCAL Location",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      const reducer = getReducer("LOCATION");
      const location = (reducer(response[0]));

      // Delete any attached addresses
      if (location.hasOwnProperty('address_iri')) {
        let addrIris = []
        if (Array.isArray(location.address_iri)) {
          addrIris = location.address_iri;
        } else {
          addrIris.push(location.address_iri);
        }
        for (let addrIri of addrIris) {
          const addrQuery = deleteAddressByIriQuery(addrIri);
          let result = await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: addrQuery,
            queryId: "Delete Address from this Location"
          }); 
        }
      }
      // Delete any attached telephone numbers
      if (location.hasOwnProperty('telephone_numbers_iri')) {
        for (const phoneIri of location.telephone_numbers_iri) {
          const phoneQuery = deletePhoneNumberByIriQuery(phoneIri);
          let result = await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: phoneQuery,
            queryId: "Delete Telephone Number from this Party"
          });
        }
      }

      // detach the Location from the parent object (if supplied)

      // Delete the Location itself
      const query = deleteLocationQuery(id);
      try {
        let result = await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: "Delete OSCAL Location"
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      return id;
    },
    editOscalLocation: async (_, { id, input }, { dbName, dataSources, selectMap }) => {
      // check that the object to be edited exists with the predicates - only get the minimum of data
      let editSelect = ['id'];
      for (let editItem of input) {
        editSelect.push(editItem.key);
      }
      const sparqlQuery = selectLocationQuery(id, editSelect );
      let response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select OSCAL Location",
        singularizeSchema
      })
      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

      // TODO: WORKAROUND to handle UI where it DOES NOT provide an explicit operation
      for (let editItem of input) {
        if (!response[0].hasOwnProperty(editItem.key)) editItem.operation = 'add';
      }
      // END WORKAROUND

      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/common#Location-${id}`,
        `http://csrc.nist.gov/ns/oscal/common#Location`,
        input,
        locationPredicateMap
      )
      await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update OSCAL Location"
      });
      const select = selectLocationQuery(id, selectMap.getNode("editOscalLocation"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select OSCAL Location",
        singularizeSchema
      });
      let reducer = getReducer("LOCATION");
      return reducer(result[0]);
    },
  },
  OscalLocation: {
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
    address: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.address_iri === undefined) return [];
      let iri = parent.address_iri[0];
      const sparqlQuery = selectAddressByIriQuery(iri, selectMap.getNode("address"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Address",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      if (response === undefined || response.length === 0) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getGlobalReducer("ADDRESS");
        return(reducer(response[0]));
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
    },
    telephone_numbers: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.telephone_numbers_iri === undefined) return [];
      let iriArray = parent.telephone_numbers_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("PHONE-NUMBER");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('TelephoneNumber')) continue;
          const sparqlQuery = selectPhoneNumberByIriQuery(iri, selectMap.getNode("telephone_numbers"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Telephone number",
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
  },
}

export default oscalLocationResolvers;