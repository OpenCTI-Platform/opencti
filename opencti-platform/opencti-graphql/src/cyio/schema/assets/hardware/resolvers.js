import { UserInputError } from 'apollo-server-express';
import { assetSingularizeSchema as singularizeSchema, objectTypeMapping } from '../asset-mappings.js';
import { compareValues, filterValues, updateQuery, CyioError } from '../../utils.js';
import { addToInventoryQuery, deleteQuery, removeFromInventoryQuery } from '../assetUtil.js';
import {
  getReducer,
  insertHardwareQuery,
  selectAllHardware,
  selectHardwareQuery,
<<<<<<< HEAD
  hardwarePredicateMap,
=======
  selectHardwareByIriQuery,
  hardwarePredicateMap, 
>>>>>>> origin/develop
  attachToHardwareQuery,
  detachFromHardwareQuery,
} from './sparql-query.js';
<<<<<<< HEAD
import { getSelectSparqlQuery } from '../computing-device/sparql-query.js';
import { selectSoftwareByIriQuery, getReducer as getSoftwareReducer } from '../software/sparql-query.js';
import { selectNetworkByIriQuery, getReducer as getNetworkReducer } from '../network/sparql-query.js';
=======
import { getSelectSparqlQuery} from '../computing-device/sparql-query.js';
import {
  selectSoftwareByIriQuery,
  getReducer as getSoftwareReducer
} from '../software/sparql-query.js';
import {
  selectNetworkByIriQuery,
  getReducer as getNetworkReducer
} from '../network/sparql-query.js';
>>>>>>> origin/develop
import {
  deleteIpQuery,
  deleteMacQuery,
  deletePortQuery,
  insertIPQuery,
  insertIPRelationship,
  insertMACQuery,
  insertMACRelationship,
  insertPortRelationships,
  insertPortsQuery,
} from '../assetQueries.js';
import {
  selectLabelByIriQuery,
  selectExternalReferenceByIriQuery,
  selectNoteByIriQuery,
  getReducer as getGlobalReducer,
} from '../../global/resolvers/sparql-query.js';
import {
  selectRiskByIriQuery,
  getReducer as getAssessmentReducer,
} from '../../risk-assessments/assessment-common/resolvers/sparql-query.js';
import { selectObjectIriByIdQuery } from '../../global/global-utils.js';

const hardwareResolvers = {
  Query: {
    hardwareAssetList: async (_, args, { dbName, dataSources, selectMap }) => {
      // TODO: WORKAROUND to remove argument fields with null or empty values
      if (args !== undefined) {
        for (const [key, value] of Object.entries(args)) {
          if (Array.isArray(args[key]) && args[key].length === 0) {
            delete args[key];
            continue;
          }
          if (value === null || value.length === 0) {
            delete args[key];
          }
        }
      }
      // END WORKAROUND

      const sparqlQuery = selectAllHardware(selectMap.getNode('node'), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: 'Select Hardware device List',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined || response.length === 0) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer('HARDWARE-DEVICE');
        let skipCount = 0;
        let filterCount;
        let resultCount;
        let limit;
        let offset;
        let limitSize;
        let offsetSize;
        limitSize = limit = args.first === undefined ? response.length : args.first;
        offsetSize = offset = args.offset === undefined ? 0 : args.offset;
        filterCount = 0;
        let hardwareList;
        if (args.orderedBy !== undefined) {
          hardwareList = response.sort(compareValues(args.orderedBy, args.orderMode));
        } else {
          hardwareList = response;
        }

        if (offset > hardwareList.length) return null;

        // for each Hardware device in the result set
        for (const hardware of hardwareList) {
          if (hardware.id === undefined) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${hardware.iri} missing field 'id'; skipping`);
            skipCount++;
            continue;
          }

          if (hardware.asset_type)
            if (offset) {
              // skip down past the offset
              offset--;
              continue;
            }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(hardware, args.filters, args.filterMode)) {
              continue;
            }
            filterCount++;
          }

          // if haven't reached limit to be returned
          if (limit) {
            const edge = {
              cursor: hardware.iri,
              node: reducer(hardware),
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
        resultCount = hardwareList.length - skipCount;
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
    hardwareAsset: async (_, { id }, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectHardwareQuery(id, selectMap.getNode('hardwareAsset'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select Hardware device',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer('HARDWARE-DEVICE');
        return reducer(response[0]);
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
    createHardwareAsset: async (_, { input }, { dbName, selectMap, dataSources }) => {
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

      let ports;
      let ipv4;
      let ipv6;
      let mac;
      let connectedNetwork;
      let installedOS;
      let installedSoftware;
      if (input.ports !== undefined) {
        ports = input.ports;
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
      // obtain the IRIs for the referenced objects so that if one doesn't exists we have created anything yet.
      if (input.connected_to_network !== undefined && input.connected_to_network !== null) {
        const query = selectObjectIriByIdQuery(input.connected_to_network, 'network');
        const result = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: query,
          queryId: 'Obtaining IRI for Network object with id',
          singularizeSchema,
        });
        if (result === undefined || result.length === 0)
          throw new CyioError(`Entity does not exist with ID ${input.connected_to_network}`);
        connectedNetwork = `<${result[0].iri}>`;
        delete input.connected_to_network;
      }
      if (input.installed_operating_system !== undefined && input.installed_operating_system !== null) {
        const query = selectObjectIriByIdQuery(input.installed_operating_system, 'operating-system');
        const result = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: query,
          queryId: 'Obtaining IRI for Operating System object with id',
          singularizeSchema,
        });
        if (result === undefined || result.length === 0)
          throw new CyioError(`Entity does not exist with ID ${input.installed_operating_system}`);
        installedOS = `<${result[0].iri}>`;
        delete input.installed_operating_system;
      }
      if (input.installed_software !== undefined && input.installed_software !== null) {
        const softwareList = [];
        for (const softwareId of input.installed_software) {
          const query = selectObjectIriByIdQuery(softwareId, 'software');
          const result = await dataSources.Stardog.queryById({
            dbName,
            sparqlQuery: query,
            queryId: 'Obtaining IRI for Software object with id',
            singularizeSchema,
          });
          if (result === undefined || result.length === 0)
            throw new CyioError(`Entity does not exist with ID ${softwareId}`);
          softwareList.push(`<${result[0].iri}>`);
        }
        installedSoftware = softwareList;
        delete input.installed_software;
      }

      const { iri, id, query } = insertHardwareQuery(input);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: query,
        queryId: 'Create Hardware Asset',
      });
      const connectQuery = addToInventoryQuery(iri);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: connectQuery,
        queryId: 'Add Hardware Asset to Inventory',
      });

      if (ports !== undefined && ports !== null) {
        const { iris: portIris, query: portsQuery } = insertPortsQuery(ports);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: portsQuery,
          queryId: 'Create Ports of Hardware Asset',
        });
        const relationshipQuery = insertPortRelationships(iri, portIris);
        await dataSources.Stardog.create({
          dbName,
          queryId: 'Add Ports to Hardware Asset',
          sparqlQuery: relationshipQuery,
        });
      }
      if (ipv4 !== undefined && ipv4 !== null) {
        const { ipIris, query } = insertIPQuery(ipv4, 4);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: 'Create IPv4 Addresses of Hardware Asset',
        });
        const relationshipQuery = insertIPRelationship(iri, ipIris);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: relationshipQuery,
          queryId: 'Add IPv4 to Hardware Asset',
        });
      }
      if (ipv6 !== undefined && ipv6 !== null) {
        const { ipIris, query } = insertIPQuery(ipv6, 6);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: 'Create IPv6 Addresses of Hardware Asset',
        });
        const relationshipQuery = insertIPRelationship(iri, ipIris);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: relationshipQuery,
          queryId: 'Add IPv6 to Hardware Asset',
        });
      }
      if (mac !== undefined && mac !== null) {
        const { macIris, query } = insertMACQuery(mac);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: 'Create MAC Addresses of Hardware Asset',
        });
        const relationshipQuery = insertMACRelationship(iri, macIris);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: relationshipQuery,
          queryId: 'Add MAC to Hardware Asset',
        });
      }
      // attach any Network(s) to Computing Device
      if (connectedNetwork !== undefined && connectedNetwork !== null) {
        const networkAttachQuery = attachToHardwareQuery(id, 'connected_to_network', connectedNetwork);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: networkAttachQuery,
          queryId: 'Attaching connected network to the Hardware device Asset',
        });
      }
      // attach Operating System to Hardware Asset
      if (installedOS !== undefined && installedOS !== null) {
        const osAttachQuery = attachToHardwareQuery(id, 'installed_operating_system', installedOS);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: osAttachQuery,
          queryId: 'Attaching Operating System to the Hardware device Asset',
        });
      }
      // attach Software to Hardware Asset
      if (installedSoftware !== undefined && installedSoftware !== null) {
        const softwareAttachQuery = attachToHardwareQuery(id, 'installed_software', installedSoftware);
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: softwareAttachQuery,
          queryId: 'Attaching Installed Software to the Hardware device asset',
        });
      }

      // retrieve information about the newly created ComputingDevice to return to the user
      const select = selectHardwareQuery(id, selectMap.getNode('createHardwareAsset'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: 'Select Hardware Device',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      const reducer = getReducer('HARDWARE-DEVICE');
      return reducer(response[0]);
    },
    deleteHardwareAsset: async (_, { id }, { dbName, dataSources }) => {
      // check that the Hardware asset exists
      const sparqlQuery = selectHardwareQuery(id, ['id', 'ports', 'ip_address', 'mac_address']);
      const response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: 'Select Hardware Asset',
        singularizeSchema,
      });
      if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);
      const reducer = getReducer('HARDWARE-DEVICE');
      const asset = reducer(response[0]);

      if (asset.hasOwnProperty('ports_iri')) {
        for (const portIri of asset.ports_iri) {
          const portQuery = deletePortQuery(portIri);
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: portQuery,
            queryId: 'Delete Port from Hardware Asset',
          });
        }
      }
      if (asset.hasOwnProperty('ip_addr_iri')) {
        for (const ipId of asset.ip_addr_iri) {
          const ipQuery = deleteIpQuery(ipId);
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: ipQuery,
            queryId: 'Delete IP from HardwareAsset',
          });
        }
      }
      if (asset.hasOwnProperty('mac_addr_iri')) {
        for (const macId of asset.mac_addr_iri) {
          const macQuery = deleteMacQuery(macId);
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: macQuery,
            queryId: 'Delete MAC from Hardware Asset',
          });
        }
      }

      const relationshipQuery = removeFromInventoryQuery(asset.iri);
      await dataSources.Stardog.delete({
        dbName,
        sparqlQuery: relationshipQuery,
        queryId: 'Delete Hardware Asset from Inventory',
      });
      const query = deleteQuery(id);
      await dataSources.Stardog.delete({
        dbName,
        sparqlQuery: query,
        queryId: 'Delete Hardware Asset',
      });
      return id;
    },
    editHardwareAsset: async (_, { id, input }, { dbName, dataSources, selectMap }) => {
      // make sure there is input data containing what is to be edited
      if (input === undefined || input.length === 0) throw new CyioError(`No input data was supplied`);

      // TODO: WORKAROUND to remove immutable fields
      input = input.filter(
        (element) => element.key !== 'id' && element.key !== 'created' && element.key !== 'modified'
      );

      // check that the object to be edited exists with the predicates - only get the minimum of data
      const editSelect = ['id', 'created', 'modified'];
      for (const editItem of input) {
        editSelect.push(editItem.key);
      }

      const sparqlQuery = selectHardwareQuery(id, editSelect);
      let response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: 'Select Hardware asset',
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

      // obtain the IRIs for the referenced objects so that if one doesn't
      // exists we have created anything yet.  For complex objects that are
      // private to this object, remove them (if needed) and add the new instances
      for (const editItem of input) {
        let value;
        let objType;
        let objArray;
        const iris = [];
        let isId = true;
        let relationshipQuery;
        let queryDetails;
        for (value of editItem.value) {
          switch (editItem.key) {
            case 'asset_type':
              isId = false;
              if (value.includes('_')) value = value.replace(/_/g, '-');
              editItem.value[0] = value;
              break;
            case 'connected_to_network':
              objType = 'network';
              break;
            case 'installed_operating_system':
              objType = 'operating-system';
              break;
            case 'installed_software':
              objType = 'software';
              break;
            case 'installed_hardware':
              objType = 'hardware';
              break;
            case 'locations':
              objType = 'location';
              break;
            case 'ipv4_address':
              isId = false;
              objArray = JSON.parse(value);

              if (editItem.operation !== 'add') {
                // find the existing IPv4 object(s) of the Hardware Asset
                for (const ipAddr of response[0].ip_address) {
                  if (ipAddr.includes('IpV4')) {
                    let ipQuery;

                    // detach the IPv4 address object
                    ipQuery = detachFromHardwareQuery(id, 'ip_address', ipAddr);
                    await dataSources.Stardog.delete({
                      dbName,
                      sparqlQuery: ipQuery,
                      queryId: 'Detach IPv4 Address from Hardware Asset',
                    });
                    // Delete the IPv4 address object since its private to the Hardware Asset
                    ipQuery = deleteIpQuery(`<${ipAddr}>`);
                    await dataSources.Stardog.delete({
                      dbName,
                      sparqlQuery: ipQuery,
                      queryId: 'Delete IPv4 Address',
                    });
                  }
                }
              }
              if (editItem.operation !== 'delete') {
                // create the new IPv4 address object(s) of the Hardware asset
                queryDetails = insertIPQuery(objArray, 6);
                await dataSources.Stardog.create({
                  dbName,
                  sparqlQuery: queryDetails.query,
                  queryId: 'Create IPv4 Addresses of Hardware Asset',
                });
                // attach the new IPv6 address object(s) to the Hardware asset
                relationshipQuery = insertIPRelationship(response[0].iri, queryDetails.ipIris);
                await dataSources.Stardog.create({
                  dbName,
                  sparqlQuery: relationshipQuery,
                  queryId: 'Add IPv4 Addresses to Hardware Asset',
                });
              }
              editItem.operation = 'skip';
              break;
            case 'ipv6_address':
              isId = false;
              objArray = JSON.parse(value);

              if (editItem.operation !== 'add') {
                // find the existing IPv6 object(s) of the Hardware Asset
                for (const ipAddr of response[0].ip_address) {
                  if (ipAddr.includes('IpV6')) {
                    let ipQuery;

                    // detach the IPv6 address object
                    ipQuery = detachFromHardwareQuery(id, 'ip_address', ipAddr);
                    await dataSources.Stardog.delete({
                      dbName,
                      sparqlQuery: ipQuery,
                      queryId: 'Detach IPv6 Address from Hardware Asset',
                    });
                    // Delete the IPv6 address object since its private to the Hardware Asset
                    ipQuery = deleteIpQuery(`<${ipAddr}>`);
                    await dataSources.Stardog.delete({
                      dbName,
                      sparqlQuery: ipQuery,
                      queryId: 'Delete IPv6 Address',
                    });
                  }
                }
              }
              if (editItem.operation !== 'delete') {
                // create the new IPv6 address object(s) of the Hardware asset
                queryDetails = insertIPQuery(objArray, 6);
                await dataSources.Stardog.create({
                  dbName,
                  sparqlQuery: queryDetails.query,
                  queryId: 'Create IPv6 Addresses of Hardware Asset',
                });
                // attach the new IPv6 address object(s) to the Hardware asset
                relationshipQuery = insertIPRelationship(response[0].iri, queryDetails.ipIris);
                await dataSources.Stardog.create({
                  dbName,
                  sparqlQuery: relationshipQuery,
                  queryId: 'Add IPv6 Addresses to Hardware Asset',
                });
              }
              editItem.operation = 'skip';
              break;
            case 'ports':
              isId = false;
              objArray = JSON.parse(value);

              if (editItem.operation !== 'add') {
                // find the existing Port object(s) of the Hardware Asset
                for (const port of response[0].ports) {
                  if (port.includes('Port')) {
                    let portQuery;

                    // detach the Port object
                    portQuery = detachFromHardwareQuery(id, 'ports', port);
                    await dataSources.Stardog.delete({
                      dbName,
                      sparqlQuery: portQuery,
                      queryId: 'Detach Port Address from Hardware Asset',
                    });
                    // Delete the Port object since its private to the Hardware Asset
                    portQuery = deletePortQuery(`<${port}>`);
                    await dataSources.Stardog.delete({
                      dbName,
                      sparqlQuery: portQuery,
                      queryId: 'Delete Port ',
                    });
                  }
                }
              }
              if (editItem.operation !== 'delete') {
                // create the new Port object(s) of the Hardware asset
                const { iris: portIris, query: portsQuery } = insertPortsQuery(objArray);
                await dataSources.Stardog.create({
                  dbName,
                  sparqlQuery: portsQuery,
                  queryId: 'Create Ports of Hardware Asset',
                });
                // attach the new Port object(s) to the Hardware asset
                relationshipQuery = insertPortRelationships(response[0].iri, portIris);
                await dataSources.Stardog.create({
                  dbName,
                  sparqlQuery: relationshipQuery,
                  queryId: 'Add Ports to Hardware Asset',
                });
              }
              editItem.operation = 'skip';
              break;
            case 'mac_address':
              isId = false;
              objArray = editItem.value;

              if (editItem.operation !== 'add') {
                // find the existing MAC Address object(s) of the Hardware Asset
                for (const macAddr of response[0].mac_address) {
                  if (macAddr.includes('MACAddress')) {
                    let macQuery;

                    // detach the MAC address object
                    macQuery = detachFromHardwareQuery(id, 'mac_address', macAddr);
                    await dataSources.Stardog.delete({
                      dbName,
                      sparqlQuery: macQuery,
                      queryId: 'Detach MAC Address from Hardware Asset',
                    });
                    // Delete the MAC address object since its private to the Hardware Asset
                    macQuery = deleteMacQuery(`<${macAddr}>`);
                    await dataSources.Stardog.delete({
                      dbName,
                      sparqlQuery: macQuery,
                      queryId: 'Delete MAC Address',
                    });
                  }
                }
              }
              if (editItem.operation !== 'delete') {
                // create the new MAC address object(s) of the Hardware asset
                queryDetails = insertMACQuery(objArray);
                await dataSources.Stardog.create({
                  dbName,
                  sparqlQuery: queryDetails.query,
                  queryId: 'Create MAC Addresses of Hardware Asset',
                });
                // attach the new MAC address object(s) to the Hardware asset
                relationshipQuery = insertMACRelationship(response[0].iri, queryDetails.ipIris);
                await dataSources.Stardog.create({
                  dbName,
                  sparqlQuery: relationshipQuery,
                  queryId: 'Add MAC Addresses to Hardware Asset',
                });
              }
              editItem.operation = 'skip';
              break;
            default:
              isId = false;
              break;
          }

          if (isId) {
            const query = selectObjectIriByIdQuery(value, objType);
            const result = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery: query,
              queryId: 'Obtaining IRI for object by id',
              singularizeSchema,
            });
            if (result === undefined || result.length === 0)
              throw new CyioError(`Entity does not exist with ID ${value}`);
            iris.push(`<${result[0].iri}>`);
          }
        }
        if (iris.length > 0) editItem.value = iris;
      }

      // build composite update query for all edit items
      const query = updateQuery(
        `http://scap.nist.gov/ns/asset-identification#Hardware-${id}`,
        'http://scap.nist.gov/ns/asset-identification#Hardware',
        input,
        hardwarePredicateMap
      );
      if (query != null) {
        response = await dataSources.Stardog.edit({
          dbName,
          sparqlQuery: query,
          queryId: 'Update Hardware Asset',
        });
        if (response !== undefined && 'status' in response) {
          if (response.ok === false || response.status > 299) {
            // Handle reporting Stardog Error
            throw new UserInputError(response.statusText, {
              error_details: response.body.message ? response.body.message : results.body,
              error_code: response.body.code ? response.body.code : 'N/A',
            });
          }
        }
      }

      // retrieve the updated contents
      const selectQuery = selectHardwareQuery(id, selectMap.getNode('editHardwareAsset'));
      let result;
      try {
        result = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: selectQuery,
          queryId: 'Select Hardware asset',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      const reducer = getReducer('HARDWARE-DEVICE');
      return reducer(result[0]);
    },
  },
  // field-level query
  HardwareAsset: {
<<<<<<< HEAD
    installed_software: async (parent, _, { dbName, dataSources, selectMap }) => {
=======
    installed_hardware: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.installed_hw_iri === undefined) return [];
      let iriArray = parent.installed_hw_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        var reducer = getReducer('HARDWARE-DEVICE');
        for (let iri of iriArray) {
          // check if this is an hardware object
          if (iri === undefined || !iri.includes('Hardware')) {
            continue;
          }

          // query for the Software based on its IRI
          let sparqlQuery = selectHardwareByIriQuery(iri, selectMap.getNode('installed_hardware'));
          const response = await dataSources.Stardog.queryById({
            dbName,
            sparqlQuery,
            queryId: "Select Installed Hardware for Hardware Asset",
            singularizeSchema
          })
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
    installed_software: async (parent, _, {dbName, dataSources, selectMap}) => {
>>>>>>> origin/develop
      if (parent.installed_sw_iri === undefined) return [];
      const iriArray = parent.installed_sw_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getSoftwareReducer('SOFTWARE-IRI');
        for (const iri of iriArray) {
          // check if this is an Software object
          if (iri === undefined || !iri.includes('Software')) {
            continue;
          }

          // query for the Software based on its IRI
          const sparqlQuery = selectSoftwareByIriQuery(iri, selectMap.getNode('installed_software'));
          const response = await dataSources.Stardog.queryById({
            dbName,
            sparqlQuery,
            queryId: 'Select Installed Software for Hardware Asset',
            singularizeSchema,
          });
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
    installed_operating_system: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.installed_os_iri === undefined) return null;
      let iri = parent.installed_os_iri;
      if (Array.isArray(iri) && iri.length > 0) {
        if (iri.length > 1) {
          console.log(
            `[CYIO] (${dbName}) CONSTRAINT-VIOLATION: ${parent.iri} 'installed_operating_system' violates maxCount constraint`
          );
          iri = parent.installed_os_iri[0];
        }
      } else {
        iri = parent.installed_os_iri;
      }

      const sparqlQuery = selectSoftwareByIriQuery(iri, selectMap.getNode('installed_operating_system'));
      const reducer = getSoftwareReducer('OS-IRI');
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select Installed Operating System for Hardware Asset',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        return reducer(response[0]);
      }
      // Handle reporting Stardog Error
      if (typeof response === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      }
    },
    ipv4_address: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.ip_addr_iri === undefined) return [];
      const iriArray = parent.ip_addr_iri;
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const results = [];
        const reducer = getReducer('IPV4-ADDR');
        const selectList = selectMap.getNode('ipv4_address');
        for (const iri of iriArray) {
          // check if this is an IPv4 object
          if (!iri.includes('IpV4Address')) {
            continue;
          }

          // query for the IP address based on its IRI
          const sparqlQuery = getSelectSparqlQuery('IPV4-ADDR', selectList, iri);
          const response = await dataSources.Stardog.queryById({
            dbName,
            sparqlQuery,
            queryId: 'Select IPv4 for Hardware Asset',
            singularizeSchema,
          });
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
    ipv6_address: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.ip_addr_iri === undefined) return [];
      const iriArray = parent.ip_addr_iri;
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const results = [];
        const reducer = getReducer('IPV6-ADDR');
        const selectList = selectMap.getNode('ipv6_address');
        for (const iri of iriArray) {
          // check if this is an IPv6 object
          if (!iri.includes('IpV6Address')) {
            continue;
          }

          // query for the IP address based on its IRI
          const sparqlQuery = getSelectSparqlQuery('IPV6-ADDR', selectList, iri);
          const response = await dataSources.Stardog.queryById({
            dbName,
            sparqlQuery,
            queryId: 'Select IPv6 for Hardware Asset',
            singularizeSchema,
          });
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
    mac_address: async (parent, _, { dbName, dataSources }) => {
      if (parent.mac_addr_iri === undefined) return [];
      const iriArray = parent.mac_addr_iri;
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const results = [];
        const reducer = getReducer('MAC-ADDR');
        // the hardwired selectList is because graphQL modeled MAC address as a string array, not object array
        const selectList = ['id', 'created', 'modified', 'mac_address_value', 'is_virtual'];
        for (const addr of iriArray) {
          // check if this is an MAC address object
          if (!addr.includes('MACAddress')) {
            continue;
          }

          // query for the MAC address based on its IRI
          const sparqlQuery = getSelectSparqlQuery('MAC-ADDR', selectList, addr);
          const response = await dataSources.Stardog.queryById({
            dbName,
            sparqlQuery,
            queryId: 'Select MAC for Hardware Asset',
            singularizeSchema,
          });
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            for (const item of response) {
              const macAddr = reducer(item);
              // disallow duplicates since we're storing only the value of the mac value
              if (results.includes(macAddr.mac_address_value)) {
                continue;
              }
              results.push(macAddr.mac_address_value); // TODO: revert back when data is returned as objects, not strings
            }
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
    ports: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.ports_iri === undefined) return [];
      const iriArray = parent.ports_iri;
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const results = [];
        const reducer = getReducer('PORT-INFO');
        const selectList = selectMap.getNode('ports');
        for (const iri of iriArray) {
          // check if this is an Port object
          if (!iri.includes('Port')) {
            continue;
          }

          // query for the IP address based on its IRI
          const sparqlQuery = getSelectSparqlQuery('PORT-INFO', selectList, iri);
          const response = await dataSources.Stardog.queryById({
            dbName,
            sparqlQuery,
            queryId: 'Select Ports for Hardware Asset',
            singularizeSchema,
          });
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
    connected_to_network: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.conn_network_iri === undefined) return null;
      let iri = parent.conn_network_iri;
      if (Array.isArray(iri) && iri.length > 0) {
        if (iri.length > 1) {
          console.log(
            `[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${parent.iri} 'connected_to_network' violates maxCount constraint`
          );
          iri = parent.conn_network_iri[0];
        }
      } else {
        iri = parent.conn_network_iri;
      }

      const sparqlQuery = selectNetworkByIriQuery(iri, selectMap.getNode('connected_to_network'));
      const reducer = getNetworkReducer('NETWORK');
      const response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: 'Select Network for Hardware Asset',
        singularizeSchema,
      });
      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        return reducer(response[0]);
      }
      // Handle reporting Stardog Error
      if (typeof response === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      }
    },
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
    external_references: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.ext_ref_iri === undefined) return [];
      const iriArray = parent.ext_ref_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer('EXTERNAL-REFERENCE');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('ExternalReference')) continue;
          const sparqlQuery = selectExternalReferenceByIriQuery(iri, selectMap.getNode('external_references'));
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
    notes: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.notes_iri === undefined) return [];
      const iriArray = parent.notes_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer('NOTE');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Note')) continue;
          const sparqlQuery = selectNoteByIriQuery(iri, selectMap.getNode('notes'));
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
    related_risks: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.related_risks === undefined) return [];
      const iriArray = parent.related_risks;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getAssessmentReducer('RISK');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Risk')) continue;
          const select = selectMap.getNode('related_risks');
          const sparqlQuery = selectRiskByIriQuery(iri, select);
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Risk',
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
  },
  HardwareKind: {
    __resolveType: (item) => {
      return objectTypeMapping[item.entity_type];
    },
  },
};

export default hardwareResolvers;
