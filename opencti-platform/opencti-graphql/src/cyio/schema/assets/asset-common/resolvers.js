import { assetSingularizeSchema as singularizeSchema, objectTypeMapping } from '../asset-mappings.js';
import {compareValues, filterValues, updateQuery, CyioError} from '../../utils.js';
import { UserInputError } from "apollo-server-express";
import { 
  getSelectSparqlQuery,
  getReducer,
  deleteMultipleAssetsQuery,
  removeMultipleAssetsFromInventoryQuery,
  deleteAssetQuery,
  removeAssetFromInventoryQuery,
  insertLocationQuery,
  selectLocationQuery,
  selectAllLocations,
  deleteLocationQuery,
  locationPredicateMap,
  selectIpAddressByIriQuery,
} from './sparql-query.js';
import {
  selectLabelByIriQuery,
  selectExternalReferenceByIriQuery,
  selectNoteByIriQuery,
  getReducer as getGlobalReducer,
} from '../../global/resolvers/sparql-query.js';
import { getReducer as getIpAddrReducer} from '../computing-device/sparql-query.js';

const assetCommonResolvers = {
  Query: {
    assetList: async ( _, args, { dbName, dataSources, selectMap }) => {
      var sparqlQuery = getSelectSparqlQuery('ASSET', selectMap.getNode("node"), undefined, args.filters );
      var reducer = getReducer('ASSET');
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Asset List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        // build array of edges
        const edges = [];
        let filterCount, resultCount, limit, offset, limitSize, offsetSize;
        limitSize = limit = (args.first === undefined ? response.length : args.first) ;
        offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
        filterCount = 0;
        let assetList ;
        if (args.orderedBy !== undefined ) {
          assetList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          assetList = response;
        }

        if (offset > assetList.length) return null;

        // for each asset in the result set
        for (let asset of assetList) {
          // skip down past the offset
          if ( offset ) {
            offset--
            continue
          }

          if (asset.id === undefined || asset.id == null ) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${asset.iri} missing field 'id'`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(asset, args.filters, args.filterMode) ) {
              continue
            }
            filterCount++;
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
          return[];
        }
      }
    },
    asset: async ( _, args, {dbName, dataSources, selectMap}) => {
      var sparqlQuery = getSelectSparqlQuery('ASSET', selectMap.getNode('asset'),args.id);
      var reducer = getReducer('ASSET');
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Asset",
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
        } else {
          return null;
        }
      }
    },
    itAssetList: async ( _, args, {dbName, dataSources, selectMap} ) => {
      const selectList = selectMap.getNode("node");
      var sparqlQuery = getSelectSparqlQuery('IT-ASSET', selectList, undefined, args.filters );
      var reducer = getReducer('IT-ASSET');
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select IT Asset List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        // build array of edges
        const edges = [];
        let filterCount, resultCount, limit, offset, limitSize, offsetSize;
        limitSize = limit = (args.first === undefined ? response.length : args.first) ;
        offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
        filterCount = 0;
        let assetList ;
        if (args.orderedBy !== undefined ) {
          assetList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          assetList = response;
        }

        if (offset > assetList.length) return null;

        // for each asset in the result set
        for (let asset of assetList) {
          // skip down past the offset
          if ( offset ) {
            offset--
            continue
          }

          if (asset.id === undefined || asset.id == null ) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${asset.iri} missing field 'id'`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(asset, args.filters, args.filterMode) ) {
              continue
            }
            filterCount++;
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
    itAsset: async ( _, args, {dbName, dataSources, selectMap}) => {
      const selectList = selectMap.getNode("itAsset")
      var sparqlQuery = getSelectSparqlQuery('IT-ASSET', selectList,args.id);
      var reducer = getReducer('IT-ASSET');
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select IT Asset",
          singularizeSchema
        })
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined ) return null;
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
        } else {
          return null;
        }
      }
    },
    assetLocationList: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllLocations(selectMap.getNode("node"), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Asset Location List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer("ASSET-LOCATION");
        let filterCount, resultCount,limit, offset, limitSize, offsetSize;
        limitSize = limit = (args.first === undefined ? response.length : args.first) ;
        offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
        filterCount = 0;
        let locationList ;
        if (args.orderedBy !== undefined ) {
          locationList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          locationList = response;
        }

        if (offset > locationList.length) return null

        // for each asset in the result set
        for (let location of locationList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (location.id === undefined || location.id == null ) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${location.iri} missing field 'id'; skipping`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(location, args.filters, args.filterMode) ) {
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
          }
        }
        if (edges.length === 0 ) return null;
        // Need to adjust limitSize in case filters were used
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
    assetLocation: async (_, {id}, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectLocationQuery(id, selectMap.getNode("assetLocation"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Asset Location",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer("ASSET-LOCATION");
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
    }
  },
  Mutation: {
    deleteAsset: async (_, {id}, {dbName, dataSources}) => {
      const dq = deleteAssetQuery(id);
      await dataSources.Stardog.delete(
      {dbName,
        sparqlQuery: dq,
        queryId: "Delete Asset"
      });
      const ra = removeAssetFromInventoryQuery(id);
      await dataSources.Stardog.delete({
        dbName,
        sparqlQuery: ra,
        queryId: "Delete Asset from Inventory"
      });
      return id;
    },
    deleteAssets: async (_, { ids }, {dbName, dataSources}) => {
      const dq = deleteMultipleAssetsQuery(ids);
      await dataSources.Stardog.delete({
        dbName,
        sparqlQuery: dq,
        queryId: "Delete Assets"
      });
      const ra = removeMultipleAssetsFromInventoryQuery(ids);
      await dataSources.Stardog.delete({
        dbName,
        sparqlQuery: ra,
        queryId: "Delete Assets from Inventory"
      });
      return ids;
    },
    createAssetLocation: async (_, {input}, {dbName, selectMap, dataSources}) => {
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

      const {id, query} = insertLocationQuery(input);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: query,
        queryId: "Create Asset Location"
      });
      const select = selectLocationQuery(id, selectMap.getNode("createAssetLocation"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select Asset Location",
        singularizeSchema
      });
      const reducer = getReducer("ASSET-LOCATION");
      return reducer(result[0]);
    },
    deleteAssetLocation: async (_, {id}, {dbName, dataSources}) => {
      const query = deleteLocationQuery(id);
      await dataSources.Stardog.delete({
        dbName,
        sparqlQuery: query,
        queryId: "Delete Asset Location"
      });
      return id;
    },
    editAssetLocation: async (_, {id, input}, {dbName, dataSources, selectMap}) => {
      // make sure there is input data containing what is to be edited
      if (input === undefined || input.length === 0) throw new CyioError(`No input data was supplied`);

      // TODO: WORKAROUND to remove immutable fields
      input = input.filter(element => (element.key !== 'id' && element.key !== 'created' && element.key !== 'modified'));

      // check that the object to be edited exists with the predicates - only get the minimum of data
      let editSelect = ['id','created','modified'];
      for (let editItem of input) {
        editSelect.push(editItem.key);
      }

      const sparqlQuery = selectLocationQuery(id, editSelect );
      let response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select Asset Location",
        singularizeSchema
      })
      if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);

      // determine operation, if missing
      for (let editItem of input) {
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
        let update = {key: "created", value:[`${timestamp}`], operation: "add"}
        input.push(update);
      }
      let operation = "replace";
      if (!response[0].hasOwnProperty('modified')) operation = "add";
      let update = {key: "modified", value:[`${timestamp}`], operation: `${operation}`}
      input.push(update);

      const query = updateQuery(
          `http://darklight.ai/ns/common#CivicLocation-${id}`,
          "http://darklight.ai/ns/common#CivicLocation",
          input,
          locationPredicateMap
      )
      await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update Asset Location"
      });
      const select = selectLocationQuery(id, selectMap.getNode("editAssetLocation"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select Asset Location",
        singularizeSchema
      });
      const reducer = getReducer("ASSET-LOCATION");
      return reducer(result[0]);
    }
  },
  // Map enum GraphQL values to data model required values
  AssetType: {
    account: 'account',
    appliance: 'appliance',
    application_software: 'application-software',
    circuit: 'circuit',
    computer_account: 'computer-account',
    computing_device: 'computing-device',
    data: 'data',
    database: 'database',
    directory_server: 'directory-server',
    dns_server: 'dns-server',
    documentary_asset: 'documentary-asset',
    email_server: 'email-server',
    embedded: 'embedded',
    firewall: 'firewall',
    guidance: 'guidance',
    hypervisor: 'hypervisor',
    laptop: 'laptop',
    load_balancer: 'load-balancer',
    mobile_device: 'mobile-device',
    network: 'network',
    network_device: 'network-device',
    operating_system: 'operating-system',
    pbx: 'pbx',
    physical_device: 'physical-device',
    plan: 'plan',
    policy: 'policy',
    printer: 'printer',
    procedure: 'procedure',
    router: 'router',
    server: 'server',
    service: 'service',
    service_account: 'service-account',
    software: 'software',
    standard: 'standard',
    storage_array: 'storage-array',
    switch: 'switch',
    system: 'system',
    user_account: 'user-account',
    validation: 'validation',
    voip_device: 'voip-device',
    voip_handset: 'voip-handset',
    voip_router: 'voip-router',
    web_server: 'web-server',
    web_site: 'web-site',
    wireless_access_point: 'wireless-access-point',
    workstation: 'workstation',
  },
  Asset: {
    __resolveType: ( item ) => {
      return objectTypeMapping[item.entity_type];
    },
    locations: async (parent, _, {dbName, dataSources, selectMap}) => {
      let iriArray = parent.labels_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer("ASSET-LOCATION");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Location')) continue;
          const sparqlQuery = selectLocationByIriQuery(iri, selectMap.getNode("locations"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Location",
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
  },
  AssetLocation: {
    __resolveType: ( item ) => {
      return objectTypeMapping[item.entity_type]
    }
  },
  HardwareAsset: {
    __resolveType: ( item ) => {
      return objectTypeMapping[item.entity_type];
    }
  },
  ItAsset: {
    __resolveType: ( item ) => {
      return objectTypeMapping[item.entity_type];
    }
  },
  AssetKind: {
    __resolveType: ( item ) => {
      return objectTypeMapping[item.entity_type];
    }
  },
  HardwareKind: {
    __resolveType: ( item ) => {
      return objectTypeMapping[item.entity_type];
    }
  },
  ItAssetKind: {
    __resolveType: ( item ) => {
      return objectTypeMapping[item.entity_type];
    }
  },
  IpAddressRange: {
    starting_ip_address: async (parent, _, {dbName, dataSources, selectMap},) => {
      if (parent.start_addr_iri === undefined && parent.starting_ip_address !== undefined) return parent.starting_ip_address;
      if (parent.start_addr_iri === undefined) {
        console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${parent.iri} missing field 'starting_ip_address'`);
        return null;
      }
      // retrieve the IPAddress object
      let addrType;
      if (parent.start_addr_iri.includes('IpV4Address')) {
        addrType = 'IPV4-ADDR';
      }
      if (parent.start_addr_iri.includes('IpV6Address')) {
        addrType = 'IPV6-ADDR';
      }

      let selectList = selectMap.getNode('starting_ip_address');
      if (selectList !== undefined ) {
        selectList = selectList.filter(i => i !== '__typename');
        if (selectList.length === 0) selectList = undefined
      }

      let sparqlQuery = selectIpAddressByIriQuery(parent.start_addr_iri, selectList === undefined ? null : selectList );
      const response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select IP Address",
        singularizeSchema
      })
      if (response === undefined) return [];
      if (Array.isArray(response) && response.length > 0) {
        let reducer = getIpAddrReducer(addrType);
        return (reducer(response[0]));
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
    ending_ip_address: async (parent, _, {dbName, dataSources, selectMap},) => {
      if (parent.ending_addr_iri === undefined && parent.ending_ip_address !== undefined) return parent.ending_ip_address;
      if (parent.ending_addr_iri === undefined) {
        console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${parent.iri} missing field 'ending_ip_address'`);
        return null;
      }
      // retrieve the IPAddress object
      let addrType, selectList;
      if (parent.start_addr_iri.includes('IpV4Address')) {
        addrType = 'IPV4-ADDR';
      }
      if (parent.start_addr_iri.includes('IpV6Address')) {
        addrType = 'IPV6-ADDR';
      }

      selectList = selectMap.getNode('ending_ip_address');
      if (selectList !== undefined ) {
        selectList = selectList.filter(i => i !== '__typename');
        if (selectList.length === 0) selectList = undefined
      }



      let sparqlQuery = selectIpAddressByIriQuery(parent.ending_addr_iri, selectList === undefined ? null : selectList );
      const response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select IP Address",
        singularizeSchema
      })
      if (response === undefined) return [];
      if (Array.isArray(response) && response.length > 0) {
        let reducer = getIpAddrReducer(addrType);
        return (reducer(response[0]));
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
  IpAddress: {
    __resolveType: ( item ) => {
      return objectTypeMapping[item.entity_type];
    },
  },
  PortRange: {
    __resolveType: ( item ) => {
      return objectTypeMapping[item.entity_type];
    }
  },
};

export default assetCommonResolvers;
