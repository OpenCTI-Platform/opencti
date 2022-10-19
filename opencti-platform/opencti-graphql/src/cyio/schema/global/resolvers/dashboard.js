import { CyioError } from '../../utils.js';
import conf from '../../../../config/conf.js';
import { 
  getReducer,
  entitiesCountQuery,
  dashboardSingularizeSchema as singularizeSchema,
} from './dashboard-sparqlQuery.js';

const cyioDashboardResolvers = {
  Query: {
    // Dashboard Workspace Wizard
    workspaceWizardConfig: async (_, args, { dbName, dataSources, selectMap }) => {
      const config = conf.get('workspaces:wizard:config');
      if (config === undefined || config.length === 0) throw new CyioError('Could not find workspace wizard configuration');
      return config;
    },
    assetsCount: async (_, args, { dbName, dataSources, selectMap }) => {
      // TODO: WORKAROUND to remove argument fields with null or empty values
      if (args !== undefined) {
        for (let [key, value] of Object.entries(args)) {
          if (Array.isArray(args[key]) && args[key].length === 0) {
            delete args[key];
            continue;
          }
          if (value === null || value.length === 0) {
            delete args[key];
            continue;
          }
          if (!Array.isArray(args[key])) {
            if (value instanceof Date ) value = value.toISOString();
            if (value.trim().length === 0) {
              delete args[key];
              continue;
            }
          }
        }
      }
      // END WORKAROUND

      if (!('type'in args) && !('field' in args)) throw new CyioError("Must specified either type or field");
      if (('field' in args) && !('match') in args) throw new CyioError(`"match" must be specified when using "field"`);
      if (('match' in args) && !('field') in args) throw new CyioError(`"field" must specified when using "match"`);

      let response;
      let query = entitiesCountQuery(args);
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: query,
          queryId: `Select Entity count of ${args.field}`,
          singularizeSchema
        });
      } catch (e) {
        console.error(e)
        throw e
      }

      // none found
      if (response === undefined || response.length === 0) return null;
      return {
        total: (response[0].total ? response[0].total : 0),
        count: (response[0].count ? response[0].count : 0)
      }
    },
    assetsTimeSeries: async (_, args, { dbName, dataSources, selectMap }) => {
      // TODO: WORKAROUND to remove argument fields with null or empty values
      if (args !== undefined) {
        for (const [key, value] of Object.entries(args)) {
          if (Array.isArray(args[key]) && args[key].length === 0) {
            delete args[key];
            continue;
          }
          if (value === null || value.length === 0) {
            delete args[key];
            continue;
          }
          if (!Array.isArray(args[key]) && value.trim().length === 0) {
            delete args[key];
          }
        }
      }
      // END WORKAROUND
    },
    assetsDistribution: async (_, args, { dbName, dataSources, selectMap }) => {
      // TODO: WORKAROUND to remove argument fields with null or empty values
      if (args !== undefined) {
        for (const [key, value] of Object.entries(args)) {
          if (Array.isArray(args[key]) && args[key].length === 0) {
            delete args[key];
            continue;
          }
          if (value === null || value.length === 0) {
            delete args[key];
            continue;
          }
          if (!Array.isArray(args[key]) && value.trim().length === 0) {
            delete args[key];
          }
        }
      }
      // END WORKAROUND
    },
    risksCount: async (_, args, { dbName, dataSources, selectMap }) => {
      // TODO: WORKAROUND to remove argument fields with null or empty values
      if (args !== undefined) {
        for (let [key, value] of Object.entries(args)) {
          if (Array.isArray(args[key]) && args[key].length === 0) {
            delete args[key];
            continue;
          }
          if (value === null || value.length === 0) {
            delete args[key];
            continue;
          }
          if (!Array.isArray(args[key])) {
            if (value instanceof Date ) value = value.toISOString();
            if (value.trim().length === 0) {
              delete args[key];
              continue;
            }
          }
        }
      }
      // END WORKAROUND

      if (!('type'in args) && !('field' in args)) throw new CyioError("Must specified either type or field");
      if (('field' in args) && !('match') in args) throw new CyioError(`"match" must be specified when using "field"`);
      if (('match' in args) && !('field') in args) throw new CyioError(`"field" must specified when using "match"`);

      let response;
      let query = entitiesCountQuery(args);
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: query,
          queryId: `Select Entity count of ${args.field}`,
          singularizeSchema
        });
      } catch (e) {
        console.error(e)
        throw e
      }

      // none found
      if (response === undefined || response.length === 0) return null;
      return {
        total: (response[0].total ? response[0].total : 0),
        count: (response[0].count ? response[0].count : 0)
      }
    },
    risksTimeSeries: async (_, args, { dbName, dataSources, selectMap }) => {
      // TODO: WORKAROUND to remove argument fields with null or empty values
      if (args !== undefined) {
        for (const [key, value] of Object.entries(args)) {
          if (Array.isArray(args[key]) && args[key].length === 0) {
            delete args[key];
            continue;
          }
          if (value === null || value.length === 0) {
            delete args[key];
            continue;
          }
          if (!Array.isArray(args[key]) && value.trim().length === 0) {
            delete args[key];
          }
        }
      }
      // END WORKAROUND
    },
    risksDistribution: async (_, args, { dbName, dataSources, selectMap }) => {
      // TODO: WORKAROUND to remove argument fields with null or empty values
      if (args !== undefined) {
        for (const [key, value] of Object.entries(args)) {
          if (Array.isArray(args[key]) && args[key].length === 0) {
            delete args[key];
            continue;
          }
          if (value === null || value.length === 0) {
            delete args[key];
            continue;
          }
          if (!Array.isArray(args[key]) && value.trim().length === 0) {
            delete args[key];
          }
        }
      }
      // END WORKAROUND
    }
  }
};

export default cyioDashboardResolvers;

