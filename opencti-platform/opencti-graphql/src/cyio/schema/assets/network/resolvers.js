import { assetSingularizeSchema as singularizeSchema } from '../asset-mappings.js';
import {
  getSelectSparqlQuery,
  getReducer,
  insertQuery,
  deleteNetworkAssetQuery
} from './sparql-query.js';
import {compareValues, generateId, DARKLIGHT_NS, updateQuery} from '../../utils.js';
import {
  deleteIpAddressRange,
  deleteIpQuery,
  insertIPAddressRangeQuery,
  insertIPAddressRangeRelationship,
  insertIPQuery,
  selectIPAddressRange
} from "../assetQueries";
import {UserInputError} from "apollo-server-express";
import {addToInventoryQuery} from "../assetUtil";
import {predicateMap} from "./sparql-query";

const networkResolvers = {
  Query: {
    networkAssetList: async ( _, args, context, info ) => {
      var sparqlQuery = getSelectSparqlQuery('NETWORK');
      var reducer = getReducer('NETWORK')
      const response = await context.dataSources.Stardog.queryAll( 
        context.dbName, 
        sparqlQuery,
        singularizeSchema,
        // args.first,       // limit
        // args.offset,      // offset
        args.filter );    // filter
      if (Array.isArray(response) && response.length > 0) {
        // build array of edges
        const edges = [];
        let limit = (args.first === undefined ? response.length : args.first) ;
        let offset = (args.offset === undefined ? 0 : args.offset) ;
        let assetList ;
        if (args.orderedBy !== undefined ) {
          assetList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          assetList = response;
        }
        for (let asset of assetList) {
          // skip down past the offset
          if ( offset ) {
            offset--
            continue
          }

          if ( limit ) {
            let edge = {
              cursor: asset.iri,
              node: reducer( asset ),
            }
            edges.push( edge )
            limit--;
          }
        }
        return {
          pageInfo: {
            startCursor: assetList[0].iri,
            endCursor: assetList[assetList.length -1 ].iri,
            hasNextPage: (args.first > assetList.length ? true : false),
            hasPreviousPage: (args.offset > 0 ? true : false),
            globalCount: assetList.length,
          },
          edges: edges,
        }
      } else {
        return ;
      }
    },
    networkAsset: async (_, args, context, info ) => {
      var sparqlQuery = getSelectSparqlQuery("NETWORK",context.selectMap.getNode("networkAsset"), args.id);
      var reducer = getReducer('NETWORK')
      const response = await context.dataSources.Stardog.queryById( context.dbName, sparqlQuery, singularizeSchema )
      if (response === undefined ) return null;
      const first = response[0];
      if (first === undefined) return null;
      const res = reducer( first );
      return res;
    }
  },
  Mutation: {
    createNetworkAsset: async ( _, {input}, context) => {
      const dbName = context.dbName;
      let ipv4RelIri = null, ipv6RelIri = null;
      if(input.network_ipv4_address_range !== undefined) {
        const ipv4Range = input.network_ipv4_address_range;
        delete input.network_ipv4_address_range;
        const {ipIris: startIris, query: startQuery } = insertIPQuery([ipv4Range.starting_ip_address], 4);
        const {ipIris: endIris, query: endQuery } = insertIPQuery([ipv4Range.ending_ip_address], 4);
        const startIri = startIris[0], endIri = endIris[0];
        await context.dataSources.Stardog.create(dbName, startQuery);
        await context.dataSources.Stardog.create(dbName, endQuery);
        const {iri, query} = insertIPAddressRangeQuery(startIri, endIri);
        ipv4RelIri = iri;
        await context.dataSources.Stardog.create(dbName, query);
      }
      if(input.network_ipv6_address_range !== undefined){
        const ipv6Range = input.network_ipv6_address_range;
        delete input.network_ipv6_address_range;
        const {ipIris: startIris, query: startQuery } = insertIPQuery([ipv6Range.starting_ip_address], 6);
        const {ipIris: endIris, query: endQuery } = insertIPQuery([ipv6Range.ending_ip_address], 6);
        const startIri = startIris[0], endIri = endIris[0];
        await context.dataSources.Stardog.create(dbName, startQuery);
        await context.dataSources.Stardog.create(dbName, endQuery);
        const {iri, query} = insertIPAddressRangeQuery(startIri, endIri);
        ipv6RelIri = iri;
        await context.dataSources.Stardog.create(dbName, query);
      }

      const {iri, id, query} = insertQuery(input);
      await context.dataSources.Stardog.create(dbName, query);

      if (ipv4RelIri !== null) {
        const relQuery = insertIPAddressRangeRelationship(iri, ipv4RelIri);
        await context.dataSources.Stardog.create(dbName, relQuery);
      }
      if (ipv6RelIri !== null){
        const relQuery = insertIPAddressRangeRelationship(iri, ipv6RelIri);
        await context.dataSources.Stardog.create(dbName, relQuery);
      }

      const connectQuery = addToInventoryQuery(iri);
      await context.dataSources.Stardog.create(dbName, connectQuery);
      return {id}
    },
    deleteNetworkAsset: async ( _, args, context, info ) => {
      const dbName = context.dbName;
      const sparqlQuery = getSelectSparqlQuery("NETWORK", ["id", "network_address_range"], args.id);
      const response = await context.dataSources.Stardog.queryById(dbName, sparqlQuery, singularizeSchema);
      if(response.length === 0) throw new UserInputError(`Entity does not exists with ID ${args.id}`);
      const reducer = getReducer("NETWORK");
      const asset = reducer(response[0]);
      if(asset.netaddr_range_iri){
        const ipRangeQuery = selectIPAddressRange(`<${asset.netaddr_range_iri}>`);
        const ipRange = await context.dataSources.Stardog.queryAll(dbName, ipRangeQuery);
        if(ipRange.length === 1){
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
    editNetworkAsset: async ( _, {id, input}, context ) => {
      const dbName = context.dbName;
      const query = updateQuery(
          `http://scap.nist.gov/ns/asset-identification#Network-${id}`,
          "http://scap.nist.gov/ns/asset-identification#Network",
          input,
          predicateMap
      )
      await context.dataSources.Stardog.edit(dbName, query);
      return {id}
    },
  },
  // Map enum GraphQL values to data model required values
  NetworkAsset: {
    network_address_range: async (parent, args, context, info) => {
      let item = parent.netaddr_range_iri;
      var sparqlQuery = selectIPAddressRange(`<${item}>`)
      var reducer = getReducer('NETADDR-RANGE');
      const response = await context.dataSources.Stardog.queryById( context.dbName, sparqlQuery, singularizeSchema )
      if (response && response.length > 0) {
        // console.log( response[0] );
        // let results = ipAddrRangeReducer( response[0] )    TODO: revert when data is passed as objects, instead of string
        let results = reducer( response[0] )
        let x = generateId( {"value": results.start_addr_iri}, DARKLIGHT_NS)
        return {
          id: results.id,
          starting_ip_address: {
            id: generateId( {"value": results.start_addr_iri}, DARKLIGHT_NS),
            entity_type: (results.start_addr_iri.includes(':') ? 'ipv6-addr' : 'ipv4-addr'),
            ip_address_value: results.start_addr_iri
          },
          ending_ip_address: {
            id: generateId( {"value": results.ending_addr_iri}, DARKLIGHT_NS),
            entity_type: (results.ending_addr_iri.includes(':') ? 'ipv6-addr' : 'ipv4-addr'),
            ip_address_value: results.ending_addr_iri
          }
        }
        // return results
      }
    }
  }
};

export default networkResolvers;
