import { UserInputError } from 'apollo-server-express';
import { riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import { compareValues, updateQuery, filterValues } from '../../../utils.js';
import {
  getReducer,
  insertComponentQuery,
  selectComponentQuery,
  selectComponentByIriQuery,
  selectAllComponents,
  deleteComponentQuery,
  deleteComponentByIriQuery,
  attachToComponentQuery,
  detachFromComponentQuery,
  convertAssetToComponent,
} from './sparql-query.js';
import { findDataMarkingByIri } from '../../../data-markings/domain/dataMarkings.js';


const componentResolvers = {
  Query: {
    componentList: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllComponents(null, args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: 'Select Component List',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      // no components found
      if (response === undefined) return null;

      // Handle reporting Stardog Error
      if (typeof response === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      }

      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer('COMPONENT');
        let filterCount;
        let resultCount;
        let limit;
        let offset;
        let limitSize;
        let offsetSize;
        limitSize = limit = args.first === undefined ? response.length : args.first;
        offsetSize = offset = args.offset === undefined ? 0 : args.offset;
        filterCount = 0;

        // compose name to include version and patch level
        for (const component of response) {
          // filter out network assets
          if (component.asset_type === 'network') continue;
          let { name } = component;
          if (name === undefined || name === null) {
            console.error(`[CYIO] INVALID-COMPONENT: (${dbName}) Unknown component name is unspecified for object ${component.iri}`);
            continue;
          }
          if (component.hasOwnProperty('vendor_name')) {
            if (!component.name.startsWith(component.vendor_name)) name = `${component.vendor_name} ${component.name}`;
          }
          if (component.hasOwnProperty('version')) name = `${name} ${component.version}`;
          if (component.hasOwnProperty('patch_level')) name = `$${name} ${component.patch_level}`;
          component.name = name;
        }

        let componentList;
        if (args.orderedBy !== undefined) {
          componentList = response.sort(compareValues(args.orderedBy, args.orderMode));
        } else {
          componentList = response;
        }

        if (offset > componentList.length) return null;

        // for each Component in the result set
        for (let component of componentList) {
          // skip down past the offset
          if (offset) {
            offset--;
            continue;
          }

          // Determine the proper component type for the asset
          if (component.component_type === undefined) {
            switch (component.asset_type) {
              case 'software':
              case 'operating-system':
              case 'application-software':
                component.component_type = 'software';
                break;
              case 'network':
                component.component_type = 'network';
                break;
              default:
                if (component.asset_type) {
                  console.error(
                    `[CYIO] INVALID-COMPONENT: (${dbName}) Invalid asset type "${component.asset_type}" specified for component ${component.iri}`
                  );
                  continue;
                }
                if (component.iri.includes('Software')) component.component_type = 'software';
                if (component.iri.includes('Network')) component.component_type = 'network';
                if (component.component_type === undefined) {
                  console.error(
                    `[CYIO] INVALID-COMPONENT: (${dbName}) Unknown component type is unspecified for object ${component.iri}`
                  );
                  continue;
                }
            }
          }

          // TODO: WORKAROUND missing component type
          if (!component.hasOwnProperty('operational_status')) {
            console.warn(
              `[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${component.iri} missing field 'operational_status'; fixing`
            );
            component.operational_status = 'operational';
          }
          // END WORKAROUND

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(component, args.filters, args.filterMode)) {
              continue;
            }
            filterCount++;
          }

          // convert the asset into a component
          component = convertAssetToComponent(component);

          // if haven't reached limit to be returned
          if (limit) {
            const edge = {
              cursor: component.iri,
              node: component,
              // node: reducer(component),
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
        resultCount = componentList.length;
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
    },
    component: async (_, { id }, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectComponentQuery(id, selectMap.getNode('component'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select Component',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      // Handle reporting Stardog Error
      if (typeof response === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      }

      if (Array.isArray(response) && response.length > 0) {
        // convert the asset into a component
        const component = convertAssetToComponent(response[0]);
        return component;
        // const reducer = getReducer("COMPONENT");
        // return reducer(response[0]);
      }
    },
  },
  Mutation: {
    createComponent: async (_, { input }, { dbName, selectMap, dataSources }) => {},
    deleteComponent: async (_, { id }, { dbName, dataSources }) => {},
    editComponent: async (_, { id, input }, { dbName, dataSources, selectMap }) => {},
  },
  Component: {
    responsible_roles: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.responsible_roles_iri === undefined) return [];
      const reducer = getCommonReducer('RESPONSIBLE-ROLE');
      const results = [];
      const sparqlQuery = selectAllResponsibleRoles(selectMap.getNode('node'), args, parent);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select Referenced Responsible Roles',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      if (response === undefined || response.length === 0) return null;

      // Handle reporting Stardog Error
      if (typeof response === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      }

      for (const item of response) {
        results.push(reducer(item));
      }

      // check if there is data to be returned
      if (results.length === 0) return [];
      return results;
    },
    protocols: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.protocols_iri === undefined) return [];
    },
    object_markings: async (parent, _, { dbName, dataSources, selectMap}) => {
      if (parent.marking_iris === undefined) return [];
      let results = []
      for (let iri of parent.marking_iris) {
        let result = await findDataMarkingByIri(iri, dbName, dataSources, selectMap.getNode('object_markings'));
        if (result === undefined || result === null) return null;
        results.push(result);
      }
      return results;
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
    links: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.links_iri === undefined) return [];
      const iriArray = parent.links_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer('EXTERNAL-REFERENCE');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('ExternalReference')) continue;
          const sparqlQuery = selectExternalReferenceByIriQuery(iri, selectMap.getNode('links'));
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
    remarks: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.remarks_iri === undefined) return [];
      const iriArray = parent.remarks_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer('NOTE');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Note')) continue;
          const sparqlQuery = selectNoteByIriQuery(iri, selectMap.getNode('remarks'));
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
  },
};

export default componentResolvers;
