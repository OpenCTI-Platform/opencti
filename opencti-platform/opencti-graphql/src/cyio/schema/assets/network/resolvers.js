import { assetSingularizeSchema as singularizeSchema } from '../asset-mappings.js';
import { UserInputError } from "apollo-server-express";
import { compareValues, filterValues, generateId, DARKLIGHT_NS, updateQuery } from '../../utils.js';
import { addToInventoryQuery } from "../assetUtil.js";
import {
  getSelectSparqlQuery,
  getReducer,
  insertQuery,
  deleteNetworkAssetQuery,
  predicateMap,
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
      var sparqlQuery = getSelectSparqlQuery('NETWORK', selectMap.getNode('node'));
      var reducer = getReducer('NETWORK')
      const response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Network Asset List",
          singularizeSchema,
        });
        // args.filter);    // filter

      if (response === undefined) return;
      if (Array.isArray(response) && response.length > 0) {
        // build array of edges
        const edges = [];
        let limit = (args.first === undefined ? response.length : args.first);
        let offset = (args.offset === undefined ? 0 : args.offset);
        const assetList = (args.orderedBy !== undefined) ? response.sort(compareValues(args.orderedBy, args.orderMode)) : response;

        if (offset > assetList.length) return

        for (let asset of assetList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (asset.id === undefined || asset.id == null) {
            console.log(`[DATA-ERROR] object ${asset.iri} is missing required properties; skipping object.`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(asset, args.filters, args.filterMode)) {
              continue
            }
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
        return {
          pageInfo: {
            startCursor: edges[0].cursor,
            endCursor: edges[edges.length - 1].cursor,
            hasNextPage: (args.first < assetList.length),
            hasPreviousPage: (args.offset > 0),
            globalCount: assetList.length,
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
          return;
        }
      }
    },
    networkAsset: async (_, args, {dbName, dataSources, selectMap}) => {
      const selectList = selectMap.getNode("networkAsset")
      var sparqlQuery = getSelectSparqlQuery('NETWORK', selectList, args.id);
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
    createNetworkAsset: async (_, { input }, {dbName, dataSources}) => {
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
        queryId: "Add Netowork Asset to Inventory"
      });
      return { id }
    },
    deleteNetworkAsset: async (_, args, {dbName, dataSources}) => {
      const sparqlQuery = getSelectSparqlQuery("NETWORK", ["id", "network_address_range"], args.id);
      const response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select Network Asset",
        singularizeSchema
      });
      if (response.length === 0) throw new UserInputError(`Entity does not exists with ID ${args.id}`);
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
          const start = ipRange[0].starting_ip_address;
          const end = ipRange[0].ending_ip_address;
          let ipQuery = deleteIpQuery(`<${start}>`);
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: ipQuery,
            queryId: "Delete Start IP"
          });
          ipQuery = deleteIpQuery(`<${end}>`);
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: ipQuery,
            queryId: "Delete End IP"
          });
        }
        const deleteIpRange = deleteIpAddressRange(`<http://scap.nist.gov/ns/asset-identification#IpAddressRange-${args.id}>`);
        await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: deleteIpRange,
          queryId: "Delete IP Range"
        });
      }
      const deleteQuery = deleteNetworkAssetQuery(args.id);
      await dataSources.Stardog.delete({
        dbName,
        sparqlQuery: deleteQuery,
        queryId: "Delete Network Asset"
      });
      return id
    },
    editNetworkAsset: async (_, { id, input }, {dbName, dataSources}) => {
      const query = updateQuery(
        `http://scap.nist.gov/ns/asset-identification#Network-${id}`,
        "http://scap.nist.gov/ns/asset-identification#Network",
        input,
        predicateMap
      )
      await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update Network Asset"
      });
      return { id }
    },
  },
  // Map enum GraphQL values to data model required values
  NetworkAsset: {
    network_address_range: async (parent, args, {dbName, dataSources},) => {
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
        return {
          id: results.id,
          starting_ip_address: {
            id: generateId({ "value": results.start_addr_iri }, DARKLIGHT_NS),
            entity_type: (results.start_addr_iri.includes(':') ? 'ipv6-addr' : 'ipv4-addr'),
            ip_address_value: results.start_addr_iri
          },
          ending_ip_address: {
            id: generateId({ "value": results.ending_addr_iri }, DARKLIGHT_NS),
            entity_type: (results.ending_addr_iri.includes(':') ? 'ipv6-addr' : 'ipv4-addr'),
            ip_address_value: results.ending_addr_iri
          }
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
    labels: async (parent, args, {dbName, dataSources, selectMap}) => {
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
    external_references: async (parent, args, {dbName, dataSources, selectMap}) => {
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
    notes: async (parent, args, {dbName, dataSources, selectMap}) => {
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
