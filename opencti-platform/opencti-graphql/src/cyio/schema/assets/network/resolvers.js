import { assetSingularizeSchema as singularizeSchema } from '../asset-mappings.js';
import {
  getSelectSparqlQuery,
  getReducer,
  insertQuery,
  deleteNetworkAssetQuery
} from './sparql-query.js';
import { compareValues, filterValues, generateId, DARKLIGHT_NS, updateQuery } from '../../utils.js';
import {
  deleteIpAddressRange,
  deleteIpQuery,
  insertIPAddressRangeQuery,
  insertIPAddressRangeRelationship,
  insertIPQuery,
  selectIPAddressRange
} from "../assetQueries.js";
import { UserInputError } from "apollo-server-express";
import { addToInventoryQuery } from "../assetUtil.js";
import { predicateMap } from "./sparql-query.js";

const networkResolvers = {
  Query: {
    networkAssetList: async (_, args, context,) => {
      var sparqlQuery = getSelectSparqlQuery('NETWORK', context.selectMap.getNode('node'));
      var reducer = getReducer('NETWORK')
      let response;
      try {
        response = await context.dataSources.Stardog.queryAll(
          context.dbName,
          sparqlQuery,
          singularizeSchema,
          // args.first,       // limit
          // args.offset,      // offset
          args.filter);    // filter
      } catch (e) {
        console.log(e)
        throw e
      }

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
    networkAsset: async (_, args, context, info) => {
      var sparqlQuery = getSelectSparqlQuery('NETWORK', context.selectMap.getNode('networkAsset'), args.id);
      var reducer = getReducer('NETWORK')
      let response;
      try {
        response = await context.dataSources.Stardog.queryById(context.dbName, sparqlQuery, singularizeSchema)
      } catch (e) {
        console.log(e)
        throw e
      }

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
    createNetworkAsset: async (_, { input }, context) => {
      const dbName = context.dbName;
      let ipv4RelIri = null, ipv6RelIri = null;
      if (input.network_ipv4_address_range !== undefined) {
        const ipv4Range = input.network_ipv4_address_range;
        delete input.network_ipv4_address_range;
        const { ipIris: startIris, query: startQuery } = insertIPQuery([ipv4Range.starting_ip_address], 4);
        const { ipIris: endIris, query: endQuery } = insertIPQuery([ipv4Range.ending_ip_address], 4);
        const startIri = startIris[0], endIri = endIris[0];
        await context.dataSources.Stardog.create(dbName, startQuery);
        await context.dataSources.Stardog.create(dbName, endQuery);
        const { iri, query } = insertIPAddressRangeQuery(startIri, endIri);
        ipv4RelIri = iri;
        await context.dataSources.Stardog.create(dbName, query);
      }
      if (input.network_ipv6_address_range !== undefined) {
        const ipv6Range = input.network_ipv6_address_range;
        delete input.network_ipv6_address_range;
        const { ipIris: startIris, query: startQuery } = insertIPQuery([ipv6Range.starting_ip_address], 6);
        const { ipIris: endIris, query: endQuery } = insertIPQuery([ipv6Range.ending_ip_address], 6);
        const startIri = startIris[0], endIri = endIris[0];
        await context.dataSources.Stardog.create(dbName, startQuery);
        await context.dataSources.Stardog.create(dbName, endQuery);
        const { iri, query } = insertIPAddressRangeQuery(startIri, endIri);
        ipv6RelIri = iri;
        await context.dataSources.Stardog.create(dbName, query);
      }

      const { iri, id, query } = insertQuery(input);
      await context.dataSources.Stardog.create(dbName, query);

      if (ipv4RelIri !== null) {
        const relQuery = insertIPAddressRangeRelationship(iri, ipv4RelIri);
        await context.dataSources.Stardog.create(dbName, relQuery);
      }
      if (ipv6RelIri !== null) {
        const relQuery = insertIPAddressRangeRelationship(iri, ipv6RelIri);
        await context.dataSources.Stardog.create(dbName, relQuery);
      }

      const connectQuery = addToInventoryQuery(iri);
      await context.dataSources.Stardog.create(dbName, connectQuery);
      return { id }
    },
    deleteNetworkAsset: async (_, args, context, info) => {
      const dbName = context.dbName;
      const sparqlQuery = getSelectSparqlQuery("NETWORK", ["id", "network_address_range"], args.id);
      const response = await context.dataSources.Stardog.queryById(dbName, sparqlQuery, singularizeSchema);
      if (response.length === 0) throw new UserInputError(`Entity does not exists with ID ${args.id}`);
      const reducer = getReducer("NETWORK");
      const asset = reducer(response[0]);
      if (asset.netaddr_range_iri) {
        const ipRangeQuery = selectIPAddressRange(`<${asset.netaddr_range_iri}>`);
        const ipRange = await context.dataSources.Stardog.queryAll(dbName, ipRangeQuery);
        if (ipRange.length === 1) {
          const start = ipRange[0].starting_ip_address;
          const end = ipRange[0].ending_ip_address;
          let ipQuery = deleteIpQuery(`<${start}>`);
          await context.dataSources.Stardog.delete(dbName, ipQuery);
          ipQuery = deleteIpQuery(`<${end}>`);
          await context.dataSources.Stardog.delete(dbName, ipQuery);
        }
        const deleteIpRange = deleteIpAddressRange(`<http://scap.nist.gov/ns/asset-identification#IpAddressRange-${args.id}>`);
        await context.dataSources.Stardog.delete(dbName, deleteIpRange);
      }
      const deleteQuery = deleteNetworkAssetQuery(args.id);
      await context.dataSources.Stardog.delete(dbName, deleteQuery);
      return id
    },
    editNetworkAsset: async (_, { id, input }, context) => {
      const dbName = context.dbName;
      const query = updateQuery(
        `http://scap.nist.gov/ns/asset-identification#Network-${id}`,
        "http://scap.nist.gov/ns/asset-identification#Network",
        input,
        predicateMap
      )
      await context.dataSources.Stardog.edit(dbName, query);
      return { id }
    },
  },
  // Map enum GraphQL values to data model required values
  NetworkAsset: {
    network_address_range: async (parent, args, context,) => {
      let item = parent.netaddr_range_iri;
      var sparqlQuery = selectIPAddressRange(`<${item}>`)
      var reducer = getReducer('NETADDR-RANGE');
      const response = await context.dataSources.Stardog.queryById(context.dbName, sparqlQuery, singularizeSchema)
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
    }
  }
};

export default networkResolvers;
