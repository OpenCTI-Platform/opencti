import { assetSingularizeSchema as singularizeSchema, objectTypeMapping } from '../asset-mappings.js';
import {getSelectSparqlQuery, getReducer, insertQuery, predicateMap} from './sparql-query.js';
import { getSelectSparqlQuery as getSoftwareQuery, 
         getReducer as getSoftwareReducer } from '../software/sparql-query.js';
import {compareValues, filterValues, updateQuery} from '../../utils.js';
import {addToInventoryQuery, deleteQuery, removeFromInventoryQuery} from "../assetUtil.js";
import {
  deleteIpQuery,
  deletePortQuery,
  insertIPQuery,
  insertIPRelationship,
  insertPortRelationships,
  insertPortsQuery
} from "../assetQueries.js";
import {UserInputError} from "apollo-server-express";

const computingDeviceResolvers = {
  Query: {
    computingDeviceAssetList: async ( _, args, context, info  ) => { 
      var sparqlQuery = getSelectSparqlQuery('COMPUTING-DEVICE', context.selectMap.getNode("node") );
      var reducer = getReducer('COMPUTING-DEVICE');
      const response = await context.dataSources.Stardog.queryAll( 
        context.dbName, 
        sparqlQuery,
        singularizeSchema,
        // args.first,       // limit
        // args.offset,      // offset
        args.filter       // filter
      )
      if (Array.isArray(response) && response.length > 0) {
        // build array of edges
        const edges = [];
        let limit = (args.first === undefined ? response.length : args.first) ;
        let offset = (args.offset === undefined ? 0 : args.offset) ;
        const assetList = (args.orderedBy !== undefined) ? response.sort(compareValues(args.orderedBy, args.orderMode)) : response;

        if (offset > assetList.length) return

        // for each asset in the result set
        for (let asset of assetList) {
          // skip down past the offset
          if ( offset ) {
            offset--
            continue
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(asset, args.filters, args.filterMode) ) {
              continue
            }
          }
          
          // check to make sure not to return more than requested
          if ( limit ) {
            let edge = {
              cursor: asset.iri,
              node: reducer( asset ),
            }
            edges.push( edge )
            limit-- ;
          }
        }
        return {
          pageInfo: {
            startCursor: edges[0].cursor,
            endCursor: edges[edges.length-1].cursor,
            hasNextPage: (args.first < assetList.length),
            hasPreviousPage: (args.offset > 0),
            globalCount: assetList.length,
          },
          edges: edges,
        }
      } else {
        return;
      }
    },
    computingDeviceAsset: async ( _, args, context, info ) => {
      var sparqlQuery = getSelectSparqlQuery('COMPUTING-DEVICE', context.selectMap.getNode('computingDeviceAsset'), args.id);
      var reducer = getReducer('COMPUTING-DEVICE');
      const response = await context.dataSources.Stardog.queryById( context.dbName, sparqlQuery, singularizeSchema )
      if (response === undefined ) return null;
      const first = response[0];
      if (first === undefined) return null;
      return( reducer( first ) );
    },
  },
  Mutation: {
    createComputingDeviceAsset: async ( _, {input}, context ) => {
      const dbName = context.dbName;
      let ports, ipv4, ipv6;
      if(input.ports !== undefined) {
        ports = input.ports
        delete input.ports;
      }
      if(input.ipv4_address !== undefined) {
        ipv4 = input.ipv4_address;
        delete input.ipv4_address;
      }
      if(input.ipv6_address !== undefined) {
        ipv6 = input.ipv6_address;
        delete input.ipv6_address;
      }
      const {iri, id, query} = insertQuery(input);
      await context.dataSources.Stardog.create(dbName, query);
      const connectQuery = addToInventoryQuery(iri);
      await context.dataSources.Stardog.create(dbName, connectQuery);
      if(ports !== null){
        const {iris: portIris, query: portsQuery} = insertPortsQuery(ports);
        await context.dataSources.Stardog.create(dbName, portsQuery);
        const relationshipQuery = insertPortRelationships(iri, portIris);
        await context.dataSources.Stardog.create(dbName, relationshipQuery);
      }
      if(ipv4 !== null) {
        const {ipIris, query} = insertIPQuery(ipv4, 4);
        await context.dataSources.Stardog.create(dbName, query);
        const relationshipQuery = insertIPRelationship(iri, ipIris);
        await context.dataSources.Stardog.create(dbName, relationshipQuery);
      }
      if(ipv6 !== null) {
        const {ipIris, query} = insertIPQuery(ipv6, 6);
        await context.dataSources.Stardog.create(dbName, query);
        const relationshipQuery = insertIPRelationship(iri, ipIris);
        await context.dataSources.Stardog.create(dbName, relationshipQuery);
      }
      return {id};
    },
    deleteComputingDeviceAsset: async ( _, {id}, context, input ) => {
      const dbName = context.dbName;
      const sparqlQuery = getSelectSparqlQuery('COMPUTING-DEVICE', id);
      const response = await context.dataSources.Stardog.queryById( context.dbName, sparqlQuery, singularizeSchema )
      const reducer = getReducer('COMPUTING-DEVICE');
      if(response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      const asset = (reducer(response[0]));
      for(const portIri of asset.ports_iri) {
        const portQuery = deletePortQuery(portIri);
        await context.dataSources.Stardog.delete(dbName, portQuery);
      }
      for(const ipId of asset.ip_addr_iri) {
        const ipQuery = deleteIpQuery(ipId);
        await context.dataSources.Stardog.delete(dbName, ipQuery);
      }
      const relationshipQuery = removeFromInventoryQuery(id);
      await context.dataSources.Stardog.delete(dbName, relationshipQuery)
      const query = deleteQuery(id)
      await context.dataSources.Stardog.delete(dbName, query)
      return {id};
    },
    editComputingDeviceAsset: async ( _, {id, input}, context ) => {
      const dbName = context.dbName;
      const query = updateQuery(
          `http://scap.nist.gov/ns/asset-identification#ComputingDevice-${id}`,
          "http://scap.nist.gov/ns/asset-identification#ComputingDevice",
          input,
          predicateMap
      )
      await context.dataSources.Stardog.edit(dbName, query);
      return {id};
    },
  },
  // Map enum GraphQL values to data model required values

  // field-level query
  ComputingDeviceAsset: {
    // installed_hardware: async ( parent, args, context, ) => {
    //   let iriArray = parent.installed_hw_iri;
    // },
    installed_software: async ( parent, args, context, ) => {
      let iriArray = parent.installed_sw_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        var reducer = getSoftwareReducer('SOFTWARE-IRI');
        let selectList = context.selectMap.getNode('installed_software');
        for (let iri of iriArray) {
          // check if this is an Software object
          if (iri === undefined || !iri.includes('Software')) {
            continue;
          }

          // query for the Software based on its IRI
          var sparqlQuery = getSoftwareQuery('SOFTWARE-IRI', selectList, iri);
          let response;
          try {
            response = await context.dataSources.Stardog.queryById( context.dbName, sparqlQuery, singularizeSchema )
          }catch(e) {
            console.log(e)
            throw e
          }
          if (response === undefined ) return [];
          if (response && response.length > 0) {
            results.push(reducer( response[0] ))
          }
        }
      
      if (results.length != iriArray.length) console.log( `software mismatch results - results: ${results.length}, IRIs: ${iriArray.length}`)
      return results;
      } else {
        return [];
      }
    },
    installed_operating_system: async ( parent, args, context, ) => {
      var iri = parent.installed_os_iri
      if (Array.isArray( iri ) && iri.length > 0) {
        if (iri.length > 1) {
          console.log(`[WARNING] ${parent.parent_iri} has ${parent.parent_iri.length} values: ${parent.installed_os_iri}`);
          iri = parent.installed_os_iri[0]
        }
      } else {
        iri = parent.installed_os_iri;
      }

      var sparqlQuery = getSoftwareQuery('OS-IRI', context.selectMap.getNode('installed_operating_system'), iri);
      var reducer = getSoftwareReducer('OS-IRI');
      let response;
      try {
        response = await context.dataSources.Stardog.queryById( context.dbName, sparqlQuery, singularizeSchema )
      }catch(e) {
        console.log(e)
        throw e
      }
      if (response === undefined ) return null;
      if (response && response.length > 0) {
        return reducer(response[0])
      }
    },
    ipv4_address: async ( parent, args, context, ) => {
      let iriArray = parent.ip_addr_iri;
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const results = [];
        var reducer = getReducer('IPV4-ADDR');
        let selectList = context.selectMap.getNode('ipv4_address');
        for (let iri of iriArray) {
          // check if this is an IPv4 object
          if (!iri.includes('IpV4Address')) {
            continue;
          }

          // query for the IP address based on its IRI
          var sparqlQuery = getSelectSparqlQuery('IPV4-ADDR', selectList, iri);
          let response;
          try {
            response = await context.dataSources.Stardog.queryById( context.dbName, sparqlQuery, singularizeSchema )
          }catch(e) {
            console.log(e)
            throw e
          }
          if (response === undefined ) return [];
          if (response && response.length > 0) {
            results.push(reducer( response[0] ))
          }
        }

        return results;
      } else {
        return [];
      }
    },
    ipv6_address: async ( parent, args, context, ) => {
      let iriArray = parent.ip_addr_iri;
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const results = [];
        var reducer = getReducer('IPV6-ADDR');
        let selectList = context.selectMap.getNode('ipv6_address');
        for (let iri of iriArray) {
          // check if this is an IPv6 object
          if (!iri.includes('IpV6Address')) {
            continue;
          }

          // query for the IP address based on its IRI
          var sparqlQuery = getSelectSparqlQuery('IPV6-ADDR', selectList, iri);
          let response;
          try {
            response = await context.dataSources.Stardog.queryById( context.dbName, sparqlQuery, singularizeSchema )
          }catch(e) {
            console.log(e)
            throw e
          }
          if (response === undefined ) return [];
          if (response.length > 0 ) {
            results.push(reducer( response[0] ))
          }
        }

        return results;
        } else {
          return [];
        }
    },
    mac_address: async ( parent, args, context, ) => {
      let iriArray = parent.mac_addr_iri;
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const results = [];
        const value_array = [];
        var reducer = getReducer('MAC-ADDR');
        let selectList = context.selectMap.getNode('mac_address');
        for (let addr of iriArray) {
          // check if this is an MAC address object
          if (!addr.includes('MACAddress')) {
            continue;
          }

          // query for the MAC address based on its IRI
          var sparqlQuery = getSelectSparqlQuery('MAC-ADDR', selectList, addr);
          let response;
          try {
            response = await context.dataSources.Stardog.queryById( context.dbName, sparqlQuery, singularizeSchema )
          }catch(e) {
            console.log(e)
            throw e
          }
          if (response === undefined ) return [];
          if (response.length > 0) {
            results.push(reducer( response[0] ) )      // TODO: revent back when data is returned as objects, not strings
            // Support for returning MAC address as a string, not a node
            value_array.push( reducer(response[0]).mac_address_value )
          }
        }

        // console.log(`value array: ${value_array}`)
        if (value_array.length != iriArray.length) console.log( `mac_addr mismatch results - results: ${results.length}, IRIs: ${iriArray.length}`)
        return value_array
        // return results;      TODO:  revert back when data is returned as objects, not strings
        } else {
          return [];
        }
    },
    ports: async ( parent, args, context, ) => {
      let iriArray = parent.ports_iri;
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const results = [];
        var reducer = getReducer('PORT-INFO');
        let selectList = context.selectMap.getNode('ports');
        for (let iri of iriArray) {
          // check if this is an Port object
          if (!iri.includes('Port')) {
            continue;
          }

          // query for the IP address based on its IRI
          var sparqlQuery = getSelectSparqlQuery('PORT-INFO', selectList, iri);
          let response;
          try {
            response = await context.dataSources.Stardog.queryById( context.dbName, sparqlQuery, singularizeSchema )
          }catch(e) {
            console.log(e)
            throw e
          }
          if (response && response.length > 0) {
            results.push(reducer( response[0] ))
          }
        }

      if (results.length != iriArray.length) console.log( `ports mismatch results - results: ${results.length}, IRIs: ${iriArray.length}`)
      return results;
      } else {
        return [];
      }
    },
  },
  ComputingDeviceKind: {
    __resolveType: ( item ) => {
      return objectTypeMapping[item.entity_type];
    }
  }
};


export default computingDeviceResolvers;
