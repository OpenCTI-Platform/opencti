import { assetSingularizeSchema as singularizeSchema } from '../asset-mappings.js';
import { getSparqlQuery, getReducer } from './sparql-query.js';
import { getSparqlQuery as getSoftwareQuery, 
         getReducer as getSoftwareReducer } from '../software/sparql-query.js';
import { compareValues } from '../../utils.js';

const computingDeviceResolvers = {
  Query: {
    computingDeviceAssetList: async ( _, args, context, info  ) => { 
      var sparqlQuery = getSparqlQuery('COMPUTING-DEVICE', );
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
        let assetList ;
        if (args.orderedBy !== undefined ) {
          assetList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          assetList = response;
        }

        // for each asset in the result set
        for (let asset of assetList) {
          // skip down past the offset
          if ( offset ) {
            offset--
            continue
          }

          // if haven't reached limit to be returned
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
            startCursor: assetList[0].iri,
            endCursor: assetList[assetList.length -1 ].iri,
            hasNextPage: (args.first > assetList.length ? true : false),
            hasPreviousPage: (args.offset > 0 ? true : false),
            globalCount: assetList.length,
          },
          edges: edges,
        }
      } else {
        return;
      }
    },
    computingDeviceAsset: async ( _, args, context, info ) => {
      var sparqlQuery = getSparqlQuery('COMPUTING-DEVICE', args.id);
      var reducer = getReducer('COMPUTING-DEVICE');
      const response = await context.dataSources.Stardog.queryById( 
        context.dbName, 
        sparqlQuery, 
        singularizeSchema 
      )
      // console.log( response[0] );
      return( reducer( response[0]) );
    },
  },
  Mutation: {
    createComputingDeviceAsset: ( parent, args, context, info ) => {
    },
    deleteComputingDeviceAsset: ( parent, args, context, info ) => {
    },
    editComputingDeviceAsset: ( parent, args, context, info ) => {
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
      var reducer = getSoftwareReducer('SOFTWARE-IRI');
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const results = [];
        for (let item of iriArray) {
          // check if this is an IPv4 object
          if (!item.includes('Software')) {
            continue;
          }

          // query for the IP address based on its IRI
          var sparqlQuery = getSoftwareQuery('SOFTWARE-IRI', item);
          const response = await context.dataSources.Stardog.queryById( 
            context.dbName, 
            sparqlQuery, 
            singularizeSchema 
          )
          if (response && response.length > 0) {
            // console.log( response[0] );
            results.push(reducer( response[0] ))
          }
        }

      return results;
      } else {
        return [];
      }
    },
    installed_operating_system: async ( parent, args, context, ) => {
      var iri = parent.installed_os_iri
      if (Array.isArray( iri ) ) {
        console.log(`[DATA-ERROR] value does not comply with spec: ${parent.installed_os_iri}`);
        if (iri.length > 0) {
          iri = parent.installed_os_iri[0]
        }
      } else {
        iri = parent.installed_os_iri;
      }
      var sparqlQuery = getSoftwareQuery('OS-IRI', iri);
      var reducer = getSoftwareReducer('OS-IRI');
      const response = await context.dataSources.Stardog.queryById( 
        context.dbName, 
        sparqlQuery, 
        singularizeSchema 
      )
      if (response && response.length > 0) {
        // console.log( response[0] );
        let results = reducer(response[0])
        return results
      }
    },
    ipv4_address: async ( parent, args, context, ) => {
      let iriArray = parent.ip_addr_iri;
      var reducer = getReducer('IPV4-ADDR');
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const results = [];
        for (let ipAddr of iriArray) {
          // check if this is an IPv4 object
          if (!ipAddr.includes('IpV4Address')) {
            continue;
          }

          // query for the IP address based on its IRI
          var sparqlQuery = getSparqlQuery('IPV4-ADDR', ipAddr);
          const response = await context.dataSources.Stardog.queryById( 
            context.dbName, 
            sparqlQuery, 
            singularizeSchema 
          )
          if (response && response.length > 0) {
            // console.log( response[0] );
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
      var reducer = getReducer('IPV6-ADDR');
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const results = [];
        for (let ipAddr of iriArray) {
          // check if this is an IPv6 object
          if (!ipAddr.includes('IpV6Address')) {
            continue;
          }

          // query for the IP address based on its IRI
          var sparqlQuery = getSparqlQuery('IPV6-ADDR', ipAddr);
          const response = await context.dataSources.Stardog.queryById( 
            context.dbName, 
            sparqlQuery, 
            singularizeSchema 
          )
          if (response.length > 0 ) {
            // console.log( response[0] );
            results.push(reducer( response[0] ))
          }
        }

        return results;
        } else {
          return [];
        }
    },
    mac_address: async ( parent, args, context,) => {
      let iriArray = parent.mac_addr_iri;
      var reducer = getReducer('MAC-ADDR');
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const results = [];
        const value_array = [];
        for (let addr of iriArray) {
          // check if this is an MAC address object
          if (!addr.includes('MACAddress')) {
            continue;
          }

          // query for the MAC address based on its IRI
          var sparqlQuery = getSparqlQuery('MAC-ADDR', addr);
          const response = await context.dataSources.Stardog.queryById( 
            context.dbName, 
            sparqlQuery, 
            singularizeSchema 
          )
          if (response.length > 0) {
            // console.log( response[0] );
            results.push(reducer( response[0] ) )      // TODO: revent back when data is returned as objects, not strings
            // Support for returning MAC address as a string, not a node
            value_array.push( reducer(response[0]).mac_address_value )
          }
        }

        // console.log(`value array: ${value_array}`)
        return value_array
        // return results;      TODO:  revert back when data is returned as objects, not strings
        } else {
          return [];
        }
    },
    ports: async ( parent, args, context, ) => {
      let iriArray = parent.ip_addr_iri;
      var reducer = getReducer('PORT-INFO');
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const results = [];
        for (let ipAddr of iriArray) {
          // check if this is an IPv4 object
          if (!ipAddr.includes('Port')) {
            continue;
          }

          // query for the IP address based on its IRI
          var sparqlQuery = getSparqlQuery('PORT-INFO', ipAddr);
          const response = await context.dataSources.Stardog.queryById( 
            context.dbName, 
            sparqlQuery, 
            singularizeSchema 
          )
          if (response && response.length > 0) {
            // console.log( response[0] );
            results.push(reducer( response[0] ))
          }
        }

      return results;
      } else {
        return [];
      }
    },
  }
};


export default computingDeviceResolvers;