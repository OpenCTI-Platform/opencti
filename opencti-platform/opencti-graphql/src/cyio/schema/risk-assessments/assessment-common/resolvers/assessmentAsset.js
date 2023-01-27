import { UserInputError } from 'apollo-server-express';
import { riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import { compareValues, updateQuery, filterValues } from '../../../utils.js';
import { getReducer as getComponentReducer, selectAllComponents } from '../../component/resolvers/sparql-query.js';
import {
  getReducer as getAssessmentPlatformReducer,
  selectAllAssessmentPlatforms,
  getReducer,
  selectAllAssessmentAssets,
  selectAssessmentAssetQuery,
} from './sparql-query.js';

const assessmentAssetResolvers = {
  Query: {
    assessmentAssets: async (_, args, { dbName, dataSources, selectMap }) => {
      const edges = [];
      const reducer = getReducer('ASSESSMENT-ASSET');
      const sparqlQuery = selectAllAssessmentAssets(selectMap.getNode('node'), args);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select All Assessment Assets',
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

      let filterCount;
      let resultCount;
      let limit;
      let offset;
      let limitSize;
      let offsetSize;
      limitSize = limit = args.first === undefined ? response.length : args.first;
      offsetSize = offset = args.offset === undefined ? 0 : args.offset;
      filterCount = 0;
      let assetList;
      if (args.orderedBy !== undefined) {
        assetList = response.sort(compareValues(args.orderedBy, args.orderMode));
      } else {
        assetList = response;
      }

      if (offset > assetList.length) return null;
      resultCount = observationList.length;
      for (const asset of assetList) {
        if (offset) {
          offset--;
          continue;
        }

        // filter out non-matching entries if a filter is to be applied
        if ('filters' in args && args.filters != null && args.filters.length > 0) {
          if (!filterValues(asset, args.filters, args.filterMode)) {
            continue;
          }
          filterCount++;
        }
        // if haven't reached limit to be returned
        if (limit) {
          const edge = {
            cursor: asset.iri,
            node: reducer(asset),
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
    },
    assessmentAsset: async (_, { id }, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAssessmentAssetQuery(id, selectMap.getNode('assessmentAsset'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select Assessment Asset',
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

      const reducer = getReducer('ASSESSMENT-ASSET');
      return reducer(response[0]);
    },
  },
  Mutation: {},
  AssessmentAsset: {
    components: async (parent, args, { dbName, dataSources, selectMap }) => {
      if (parent.components_iri === undefined) return null;
      const edges = [];
      const reducer = getComponentReducer('COMPONENT');
      const sparqlQuery = selectAllComponents(selectMap.getNode('node'), args, parent);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: 'Select Components',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      // no components found
      if (response === undefined || response.length === 0) return null;

      // Handle reporting Stardog Error
      if (typeof response === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      }
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
        let { name } = component;
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
      resultCount = componentList.length;
      for (const component of componentList) {
        if (offset) {
          offset--;
          continue;
        }

        // filter out non-matching entries if a filter is to be applied
        if ('filters' in args && args.filters != null && args.filters.length > 0) {
          if (!filterValues(component, args.filters, args.filterMode)) {
            continue;
          }
          filterCount++;
        }
        // if haven't reached limit to be returned
        if (limit) {
          const edge = {
            cursor: component.iri,
            node: reducer(component),
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
    },
    assessment_platforms: async (parent, args, { dbName, dataSources, selectMap }) => {
      if (parent.assessment_platforms_iri === undefined) return null;
      const edges = [];
      const reducer = getAssessmentPlatformReducer('ASSESSMENT-PLATFORM');
      const sparqlQuery = selectAllAssessmentPlatforms(selectMap.getNode('node'), args, parent);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: 'Select Assessment Platforms',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      // no components found
      if (response === undefined || response.length === 0) return null;

      // Handle reporting Stardog Error
      if (typeof response === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      }
      let filterCount;
      let resultCount;
      let limit;
      let offset;
      let limitSize;
      let offsetSize;
      limitSize = limit = args.first === undefined ? response.length : args.first;
      offsetSize = offset = args.offset === undefined ? 0 : args.offset;
      filterCount = 0;
      let platformList;
      if (args.orderedBy !== undefined) {
        platformList = response.sort(compareValues(args.orderedBy, args.orderMode));
      } else {
        platformList = response;
      }

      if (offset > platformList.length) return null;
      resultCount = platformList.length;
      for (const platform of platformList) {
        if (offset) {
          offset--;
          continue;
        }

        // filter out non-matching entries if a filter is to be applied
        if ('filters' in args && args.filters != null && args.filters.length > 0) {
          if (!filterValues(platform, args.filters, args.filterMode)) {
            continue;
          }
          filterCount++;
        }
        // if haven't reached limit to be returned
        if (limit) {
          const edge = {
            cursor: platform.iri,
            node: reducer(platform),
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
    },
  },
};

export default assessmentAssetResolvers;
