import { CyioError } from '../../utils.js';
import conf from '../../../../config/conf.js';
import { 
  getReducer,
  entitiesCountQuery,
  entitiesTimeSeriesQuery,
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

      if (!('type'in args) && !('field' in args)) throw new CyioError(`Must specify either "type" or "field"`);
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

      if (!('type'in args) && !('field' in args)) throw new CyioError(`Must specify either "type" or "field"`);
      if (('field' in args) && !('match') in args) throw new CyioError(`"match" must be specified when using "field"`);
      if (('match' in args) && !('field') in args) throw new CyioError(`"field" must specified when using "match"`);

      let response;
      let query = entitiesTimeSeriesQuery(args);
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: query,
          queryId: `Select Time Series of Entity`,
          singularizeSchema
        });
      } catch (e) {
        console.error(e)
        throw e
      }

      // none found
      if (response === undefined || response.length === 0) return null; 
      if (Object.entries(response[0]).length === 0) return null;
      let bucket = {};

      // walk the array of responses
      for (let value of response) {
        let valueTimestamp = value.created;
        let year = valueTimestamp.getFullYear().toString();
        let dateValue = new Date(valueTimestamp.setUTCHours(0,0,0,0));
        let label;
        switch(args.interval) {
          case 'day':
            label = `${valueTimestamp.toLocaleString('default',{month:'short'})} ${valueTimestamp.getDate()}`;
            break;
          case 'week':
            let startDate = new Date(valueTimestamp.getFullYear(), 0, 1);
            let numberOfDays = Math.floor((valueTimestamp - startDate) / (24 * 60 * 60 * 1000));
            let weekNumber = Math.ceil((valueTimestamp.getDay() + 1 + numberOfDays) / 7);
            label = `Wk ${weekNumber} ${year}`;
            break;
          case 'month':
            label = `${valueTimestamp.toLocaleString('default',{month:'short'})} ${year}`;
            break;
          case 'year':
            label = year;
            break;
          default:
            break;
        } 

        // build a dictionary based on the labels since they are unique
        if (label in bucket) {
          bucket[label].value++;
        } else
          bucket[label] = {date: dateValue, label: label, value: 1};
      }

      let results = [];
      for (let key in bucket) {
        results.push(bucket[key]);
      }

      return results;
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

      if (!('type'in args) && !('field' in args)) throw new CyioError(`Must specify either "type" or "field"`);
      if (('field' in args) && !('match') in args) throw new CyioError(`"match" must be specified when using "field"`);
      if (('match' in args) && !('field') in args) throw new CyioError(`"field" must specified when using "match"`);

      let response;
      let query = entitiesTimeSeriesQuery(args);
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: query,
          queryId: `Select Time Series of Entity`,
          singularizeSchema
        });
      } catch (e) {
        console.error(e)
        throw e
      }

      // none found
      if (response === undefined || response.length === 0 ) return null; 
      if (Object.entries(response[0]).length === 0) return null;
      let bucket = {};

      // walk the array of responses
      for (let value of response) {
        let valueTimestamp = value.created;
        let year = valueTimestamp.getFullYear().toString();
        let dateValue = new Date(valueTimestamp.setUTCHours(0,0,0,0));
        let label;
        switch(args.interval) {
          case 'day':
            label = `${valueTimestamp.toLocaleString('default',{month:'short'})} ${valueTimestamp.getDate()}`;
            break;
          case 'week':
            let startDate = new Date(valueTimestamp.getFullYear(), 0, 1);
            let numberOfDays = Math.floor((valueTimestamp - startDate) / (24 * 60 * 60 * 1000));
            let weekNumber = Math.ceil((valueTimestamp.getDay() + 1 + numberOfDays) / 7);
            label = `Wk ${weekNumber} ${year}`;
            break;
          case 'month':
            label = `${valueTimestamp.toLocaleString('default',{month:'short'})} ${year}`;
            break;
          case 'year':
            label = year;
            break;
          default:
            break;
        } 

        // build a dictionary based on the labels since they are unique
        if (label in bucket) {
          bucket[label].value++;
        } else
          bucket[label] = {date: dateValue, label: label, value: 1};
      }

      let results = [];
      for (let key in bucket) {
        results.push(bucket[key]);
      }

      return results;
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

