import { assetSingularizeSchema as singularizeSchema, objectTypeMapping } from '../asset-mappings.js';
import { getSelectSparqlQuery, getReducer, insertQuery, predicateMap } from './sparql-query.js';
import {
  getSelectSparqlQuery as getSoftwareQuery,
  getReducer as getSoftwareReducer
} from '../software/sparql-query.js';
import {
  getSelectSparqlQuery as getNetworkQuery,
  getReducer as getNetworkReducer
} from '../network/sparql-query.js';
import { compareValues, filterValues, updateQuery } from '../../utils.js';
import { addToInventoryQuery, deleteQuery, removeFromInventoryQuery } from "../assetUtil.js";
import {
  deleteIpQuery,
  deleteMacQuery,
  deletePortQuery,
  insertIPQuery,
  insertIPRelationship,
  insertMACQuery,
  insertMACRelationship,
  insertPortRelationships,
  insertPortsQuery
} from "../assetQueries.js";
import { UserInputError } from "apollo-server-express";

const computingDeviceResolvers = {
  Query: {
    computingDeviceAssetList: async (_, args, {dbName, dataSources, selectMap}) => {
      const selectList = selectMap.getNode("node")
      const sparqlQuery = getSelectSparqlQuery('COMPUTING-DEVICE', selectList);
      const reducer = getReducer('COMPUTING-DEVICE');
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Computing Device Asset List",
          singularizeSchema
        });
        // args.first,       // limit
        // args.offset,      // offset
        //args.filter       // filter
      } catch(e){
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

        // for each asset in the result set
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

          // check to make sure not to return more than requested
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
        }
      }
    },
    computingDeviceAsset: async (_, args, {dbName, dataSources, selectMap}) => {
      var sparqlQuery = getSelectSparqlQuery('COMPUTING-DEVICE',selectMap.getNode('computingDeviceAsset'), args.id);
      var reducer = getReducer('COMPUTING-DEVICE');
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Computing Device Asset",
          singularizeSchema
        })
      } catch (e) {
        console.log(e)
        throw e
      }
      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const first = response[0];
        if (first === undefined) return null;
        return (reducer(first));
      } else {
        // Handle reporting Stardog Error
        if (typeof (response) === 'object' && 'body' in response) {
          throw new UserInputError(response.statusText, {
            error_details: (response.body.message ? response.body.message : response.body),
            error_code: (response.body.code ? response.body.code : 'N/A')
          });
        }
      }
    },
  },
  Mutation: {
    createComputingDeviceAsset: async (_, { input }, {dbName, dataSources}) => {
      let ports, ipv4, ipv6, mac;
      if (input.ports !== undefined) {
        ports = input.ports
        delete input.ports;
      }
      if (input.ipv4_address !== undefined) {
        ipv4 = input.ipv4_address;
        delete input.ipv4_address;
      }
      if (input.ipv6_address !== undefined) {
        ipv6 = input.ipv6_address;
        delete input.ipv6_address;
      }
      if (input.mac_address !== undefined) {
        mac = input.mac_address;
        delete input.mac_address;
      }
      const { iri, id, query } = insertQuery(input);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: query,
        queryId: "Create Computing Device Asset"
      });
      const connectQuery = addToInventoryQuery(iri);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: connectQuery,
        queryId: "Add Computing Device Asset to Inventory"
      });

      if (ports !== undefined && ports !== null) {
        const { iris: portIris, query: portsQuery } = insertPortsQuery(ports);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: portsQuery,
          queryId: "Create Computing Device Asset Ports"
        });
        const relationshipQuery = insertPortRelationships(iri, portIris);
        await dataSources.Stardog.create({
          dbName,
          queryId: "Add Ports to Computing Device Asset",
          sparqlQuery: relationshipQuery
        });
      }
      if (ipv4 !== undefined && ipv4 !== null) {
        const { ipIris, query } = insertIPQuery(ipv4, 4);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: "Creat Computing Device Asset IPv4"
        });
        const relationshipQuery = insertIPRelationship(iri, ipIris);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: relationshipQuery,
          queryId: "Add IPv4 to Computing Device Asset"
        });
      }
      if (ipv6 !== undefined && ipv6!== null) {
        const { ipIris, query } = insertIPQuery(ipv6, 6);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: "Create Computing Device Asset IPv6"
        });
        const relationshipQuery = insertIPRelationship(iri, ipIris);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: relationshipQuery,
          queryId: "Add IPv6 to Computing Device Asset"
        });
      }
      if (mac !== undefined && mac!== null) {
        const { macIris, query } = insertMACQuery(mac);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: "Create Computing Device Asset MAC"
        });
        const relationshipQuery = insertMACRelationship(iri, macIris);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: relationshipQuery,
          queryId: "Add MAC to Computing Device Asset"
        });
      }
      return { id };
    },
    deleteComputingDeviceAsset: async (_, { id }, context, input) => {
      const dbName = context.dbName;
      const sparqlQuery = getSelectSparqlQuery('COMPUTING-DEVICE', id);
      const reducer = getReducer('COMPUTING-DEVICE');
      const response = await context.dataSources.Stardog.queryById(context.dbName, sparqlQuery, singularizeSchema)
      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      const asset = (reducer(response[0]));
      for (const portIri of asset.ports_iri) {
        const portQuery = deletePortQuery(portIri);
        await context.dataSources.Stardog.delete(dbName, portQuery);
      }
      for (const ipId of asset.ip_addr_iri) {
        const ipQuery = deleteIpQuery(ipId);
        await context.dataSources.Stardog.delete(dbName, ipQuery);
      }
      for (const macId of asset.mac_addr_iri) {
        const macQuery = deleteMacQuery(macId);
        await context.dataSources.Stardog.delete(dbName, macQuery);
      }

      const relationshipQuery = removeFromInventoryQuery(id);
      await context.dataSources.Stardog.delete(dbName, relationshipQuery)
      const query = deleteQuery(id)
      await context.dataSources.Stardog.delete(dbName, query)
      return { id };
    },
    editComputingDeviceAsset: async (_, { id, input }, context) => {
      const dbName = context.dbName;
      const query = updateQuery(
        `http://scap.nist.gov/ns/asset-identification#ComputingDevice-${id}`,
        "http://scap.nist.gov/ns/asset-identification#ComputingDevice",
        input,
        predicateMap
      )
      await context.dataSources.Stardog.edit(dbName, query);
      return { id };
    },
  },
  // Map enum GraphQL values to data model required values

  // field-level query
  ComputingDeviceAsset: {
    installed_software: async (parent, args, context,) => {
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
            response = await context.dataSources.Stardog.queryById(context.dbName, sparqlQuery, singularizeSchema)
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
    installed_operating_system: async (parent, args, context,) => {
      var iri = parent.installed_os_iri
      if (Array.isArray(iri) && iri.length > 0) {
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
        response = await context.dataSources.Stardog.queryById(context.dbName, sparqlQuery, singularizeSchema)
      } catch (e) {
        console.log(e)
        throw e
      }
      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        return reducer(response[0])
      } else {
        // Handle reporting Stardog Error
        if (typeof (response) === 'object' && 'body' in response) {
          throw new UserInputError(response.statusText, {
            error_details: (response.body.message ? response.body.message : response.body),
            error_code: (response.body.code ? response.body.code : 'N/A')
          });
        }
      }
    },
    ipv4_address: async (parent, args, context,) => {
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
            response = await context.dataSources.Stardog.queryById(context.dbName, sparqlQuery, singularizeSchema)
          } catch (e) {
            console.log(e)
            throw e
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]))
          } else {
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
    ipv6_address: async (parent, args, context,) => {
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
            response = await context.dataSources.Stardog.queryById(context.dbName, sparqlQuery, singularizeSchema)
          } catch (e) {
            console.log(e)
            throw e
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]))
          } else {
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
    mac_address: async (parent, args, context,) => {
      let iriArray = parent.mac_addr_iri;
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const results = [];
        var reducer = getReducer('MAC-ADDR');
        // the hardwired selectList is because graphQL modeled MAC address as a string array, not object array
        let selectList = ["id", "created", "modified", "mac_address_value", "is_virtual"];
        for (let addr of iriArray) {
          // check if this is an MAC address object
          if (!addr.includes('MACAddress')) {
            continue;
          }

          // query for the MAC address based on its IRI
          var sparqlQuery = getSelectSparqlQuery('MAC-ADDR', selectList, addr);
          let response;
          try {
            response = await context.dataSources.Stardog.queryById(context.dbName, sparqlQuery, singularizeSchema)
          } catch (e) {
            console.log(e)
            throw e
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            for (let item of response ) {
              let macAddr = reducer(item);
              // disallow duplicates since we're storing only the value of the mac value
              if( results.includes(macAddr.mac_address_value)) { continue; }
              results.push(macAddr.mac_address_value);  // TODO: revert back when data is returned as objects, not strings
            }
          } else {
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
    ports: async (parent, args, context,) => {
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
            response = await context.dataSources.Stardog.queryById(context.dbName, sparqlQuery, singularizeSchema)
          } catch (e) {
            console.log(e)
            throw e
          }
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]))
          } else {
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
    connected_to_network: async (parent, args, context,) => {
      let iri = parent.conn_network_iri;
      if (Array.isArray(iri) && iri.length > 0) {
        if (iri.length > 1) {
          console.log(`[WARNING] ${parent.conn_network_iri} has ${iri.length} values: ${parent.conn_network_iri}`);
          iri = parent.conn_network_iri[0]
        }
      } else {
        iri = parent.conn_network_iri;
      }

      let selectList = context.selectMap.getNode('connected_to_network');
      var sparqlQuery = getNetworkQuery('CONN-NET-IRI', selectList, iri);
      var reducer = getNetworkReducer('NETWORK');
      let response;
      try {
        response = await context.dataSources.Stardog.queryById(context.dbName, sparqlQuery, singularizeSchema)
      } catch (e) {
        console.log(e)
        throw e
      }
      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        return reducer(response[0])
      } else {
        // Handle reporting Stardog Error
        if (typeof (response) === 'object' && 'body' in response) {
          throw new UserInputError(response.statusText, {
            error_details: (response.body.message ? response.body.message : response.body),
            error_code: (response.body.code ? response.body.code : 'N/A')
          });
        }
      }
    }
  },
  ComputingDeviceKind: {
    __resolveType: (item) => {
      return objectTypeMapping[item.entity_type];
    }
  }
};


export default computingDeviceResolvers;
