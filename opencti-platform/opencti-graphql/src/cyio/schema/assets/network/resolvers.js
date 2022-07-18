import { assetSingularizeSchema as singularizeSchema } from '../asset-mappings.js';
import { UserInputError } from "apollo-server-express";
import { compareValues, filterValues, generateId, DARKLIGHT_NS, updateQuery } from '../../utils.js';
import { addToInventoryQuery, removeFromInventoryQuery } from "../assetUtil.js";
import {
  getReducer,
  insertQuery,
  deleteNetworkAssetQuery,
  selectAllNetworks,
  selectNetworkQuery,
  networkPredicateMap,
} from './sparql-query.js';
import {
  deleteIpAddressRange,
  deleteIpQuery,
  insertIPAddressRangeQuery,
  insertIPAddressRangeRelationship,
  insertIPQuery,
  selectIPAddressRange
} from "../assetQueries.js";
import {
  selectLabelByIriQuery,
  selectExternalReferenceByIriQuery,
  selectNoteByIriQuery,
  getReducer as getGlobalReducer,
} from '../../global/resolvers/sparql-query.js';

const networkResolvers = {
  Query: {
    networkAssetList: async (_, args, {dbName, dataSources, selectMap}) => {
      const sparqlQuery = selectAllNetworks(selectMap.getNode("node"), args);
      let reducer = getReducer('NETWORK')
      const response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Network Asset List",
          singularizeSchema,
        });

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        // build array of edges
        const edges = [];
        let filterCount, resultCount, limit, offset, limitSize, offsetSize;
        limitSize = limit = (args.first === undefined ? response.length : args.first) ;
        offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
        filterCount = 0;
        const assetList = (args.orderedBy !== undefined) ? response.sort(compareValues(args.orderedBy, args.orderMode)) : response;

        if (offset > assetList.length) return null;

        for (let asset of assetList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (asset.id === undefined || asset.id == null) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${asset.iri} missing field 'id'; skipping`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(asset, args.filters, args.filterMode)) {
              continue
            }
            filterCount++;
          }

          if (limit) {
            let edge = {
              cursor: asset.iri,
              node: reducer(asset),
            }
            edges.push(edge)
            limit--;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0 ) return null;
        let hasNextPage = false, hasPreviousPage = false;
        resultCount = assetList.length;
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
    networkAsset: async (_, {id}, {dbName, dataSources, selectMap}) => {
      const sparqlQuery = selectNetworkQuery(id, selectMap.getNode("networkAsset"));
      var reducer = getReducer('NETWORK')
      const response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select Network Asset",
        singularizeSchema
      });

      if (response === undefined) return;
      if (Array.isArray(response) && response.length > 0) {
        const first = response[0];
        if (first === undefined) return;
        return (reducer(first));
      } else {
        // Handle reporting Stardog Error
        if (typeof (response) === 'object' && 'body' in response) {
          throw new UserInputError(response.statusText, {
            error_details: (response.body.message ? response.body.message : response.body),
            error_code: (response.body.code ? response.body.code : 'N/A')
          });
        } else {
          return;
        }
      }
    }
  },
  Mutation: {
    createNetworkAsset: async (_, { input }, {dbName, dataSources, selectMap}) => {
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

      let ipv4RelIri = null, ipv6RelIri = null;
      if (input.network_ipv4_address_range !== undefined) {
        const ipv4Range = input.network_ipv4_address_range;
        delete input.network_ipv4_address_range;
        const { ipIris: startIris, query: startQuery } = insertIPQuery([ipv4Range.starting_ip_address], 4);
        const { ipIris: endIris, query: endQuery } = insertIPQuery([ipv4Range.ending_ip_address], 4);
        const startIri = startIris[0], endIri = endIris[0];
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: startQuery,
          queryId: "Create Starting IPv4 for Network Asset"
        });
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: endQuery,
          queryId: "Create Ending IPv4 for Network Asset"
        });
        const { iri, query } = insertIPAddressRangeQuery(startIri, endIri);
        ipv4RelIri = iri;
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: "Add IPv4 Range to Network Asset"
        });
      }
      if (input.network_ipv6_address_range !== undefined) {
        const ipv6Range = input.network_ipv6_address_range;
        delete input.network_ipv6_address_range;
        const { ipIris: startIris, query: startQuery } = insertIPQuery([ipv6Range.starting_ip_address], 6);
        const { ipIris: endIris, query: endQuery } = insertIPQuery([ipv6Range.ending_ip_address], 6);
        const startIri = startIris[0], endIri = endIris[0];
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: startQuery,
          queryId: "Create Starting IPv6 for Network Asset"
        });
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: endQuery,
          queryId: "Create Ending IPv6 for Network Asset"
        });
        const { iri, query } = insertIPAddressRangeQuery(startIri, endIri);
        ipv6RelIri = iri;
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: "Add IPv6 Range to Network Asset"
        });
      }

      const { iri, id, query } = insertQuery(input);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: query,
        queryId: "Create Network Asset"
      });

      if (ipv4RelIri !== null) {
        const relQuery = insertIPAddressRangeRelationship(iri, ipv4RelIri);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: relQuery,
          queryId: "Add IPv4 Range to Network Asset"
        });
      }
      if (ipv6RelIri !== null) {
        const relQuery = insertIPAddressRangeRelationship(iri, ipv6RelIri);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: relQuery,
          queryId: "Add IPv6 Range to Network Asset"
        });
      }

      const connectQuery = addToInventoryQuery(iri);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: connectQuery,
        queryId: "Add Network Asset to Inventory"
      });

      // retrieve information about the newly created Network to return to the user
      const select = selectNetworkQuery(id, selectMap.getNode("createNetworkAsset"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: "Select Network Device",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      const reducer = getReducer("NETWORK");
      return reducer(response[0]);
    },
    deleteNetworkAsset: async (_, {id}, {dbName, dataSources}) => {
      const sparqlQuery = selectNetworkQuery(id, ["id", "network_address_range"]);
      const response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select Network Asset",
        singularizeSchema
      });
      if (response.length === 0) throw new UserInputError(`Entity does not exists with ID ${id}`);
      const reducer = getReducer("NETWORK");
      const asset = reducer(response[0]);
      if (asset.netaddr_range_iri) {
        const ipRangeQuery = selectIPAddressRange(`<${asset.netaddr_range_iri}>`);
        const ipRange = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery: ipRangeQuery,
          queryId: "Select IP Range from Network Asset"
        });
        if (ipRange.length === 1) {
          const rangeId = (Array.isArray(ipRange[0].id) ? ipRange[0].id[0] : ipRange[0].id);
          const start = (Array.isArray(ipRange[0].starting_ip_address) ? ipRange[0].starting_ip_address[0] : ipRange[0].starting_ip_address);
          const end = (Array.isArray(ipRange[0].ending_ip_address) ? ipRange[0].ending_ip_address[0] : ipRange[0].ending_ip_address);
          if (start.includes('IpV4') || start.includes('IpV6')) {
            let ipQuery = deleteIpQuery(`<${start}>`);
            await dataSources.Stardog.delete({
              dbName,
              sparqlQuery: ipQuery,
              queryId: "Delete Start IP"
            });  
          }
          if (end.includes('IpV4') || end.includes('IpV6')) {
            let ipQuery = deleteIpQuery(`<${end}>`);
            await dataSources.Stardog.delete({
              dbName,
              sparqlQuery: ipQuery,
              queryId: "Delete End IP"
            });
          }
          const deleteIpRange = deleteIpAddressRange(`<http://scap.nist.gov/ns/asset-identification#IpAddressRange-${rangeId}>`);
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: deleteIpRange,
            queryId: "Delete IP Range"
          });
        }
      }
      const relationshipQuery = removeFromInventoryQuery(id);
      await dataSources.Stardog.delete({
        dbName,
        sparqlQuery: relationshipQuery,
        queryId: "Delete Network Asset from Inventory"
      })
      const deleteQuery = deleteNetworkAssetQuery(id);
      await dataSources.Stardog.delete({
        dbName,
        sparqlQuery: deleteQuery,
        queryId: "Delete Network Asset"
      });
      return id;
    },
    editNetworkAsset: async (_, { id, input }, {dbName, dataSources, selectMap}) => {
      // check that the object to be edited exists with the predicates - only get the minimum of data
      let editSelect = ['id'];
      for (let editItem of input) {
        editSelect.push(editItem.key);
      }
      const sparqlQuery = selectNetworkQuery(id, editSelect );
      let response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select Hardware asset",
        singularizeSchema
      })
      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

      // TODO: WORKAROUND to handle UI where it DOES NOT provide an explicit operation
      for (let editItem of input) {
        if (!response[0].hasOwnProperty(editItem.key)) editItem.operation = 'add';
      }
      // END WORKAROUND
      const query = updateQuery(
        `http://scap.nist.gov/ns/asset-identification#Network-${id}`,
        "http://scap.nist.gov/ns/asset-identification#Network",
        input,
        networkPredicateMap
      )
      await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update Network Asset"
      });
      const selectQuery = selectNetworkQuery(id, selectMap.getNode("editNetworkAsset"));
      let result;
      try {
        result = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: selectQuery,
          queryId: "Select Network asset",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      const reducer = getReducer("NETWORK");
      return reducer(result[0]);
    },
  },
  // Map enum GraphQL values to data model required values
  NetworkAsset: {
    network_address_range: async (parent, _, {dbName, dataSources},) => {
      let item = parent.netaddr_range_iri;
      if (item === undefined) return null;
      var sparqlQuery = selectIPAddressRange(`<${item}>`)
      var reducer = getReducer('NETADDR-RANGE');
      const response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select IP Range for Network Asset",
        singularizeSchema
      });
      if (response === undefined) return null;

      if (Array.isArray(response) && response.length > 0) {
        let results = reducer(response[0])
        if (results.hasOwnProperty('start_addr')) {
          return {
            id: results.id,
            starting_ip_address: {
              id: generateId({ "value": results.start_addr }, DARKLIGHT_NS),
              entity_type: (results.start_addr.includes(':') ? 'ipv6-addr' : 'ipv4-addr'),
              ip_address_value: results.start_addr
            },
            ending_ip_address: {
              id: generateId({ "value": results.ending_addr }, DARKLIGHT_NS),
              entity_type: (results.ending_addr.includes(':') ? 'ipv6-addr' : 'ipv4-addr'),
              ip_address_value: results.ending_addr
            }
          }
        }
        if (results.hasOwnProperty('start_addr_iri')) {
          return results;
        }
      }

      // Handle reporting Stardog Error
      if (typeof (response) === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: (response.body.message ? response.body.message : response.body),
          error_code: (response.body.code ? response.body.code : 'N/A')
        });
      }
    },
    labels: async (parent, _, {dbName, dataSources, selectMap}) => {
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
    external_references: async (parent, _, {dbName, dataSources, selectMap}) => {
      let iriArray = parent.ext_ref_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("EXTERNAL-REFERENCE");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('ExternalReference')) continue;
          const sparqlQuery = selectExternalReferenceByIriQuery(iri, selectMap.getNode("external_references"));
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
    notes: async (parent, _, {dbName, dataSources, selectMap}) => {
      let iriArray = parent.notes_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("NOTE");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Note')) continue;
          const sparqlQuery = selectNoteByIriQuery(iri, selectMap.getNode("notes"));
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
  }
};

export default networkResolvers;
