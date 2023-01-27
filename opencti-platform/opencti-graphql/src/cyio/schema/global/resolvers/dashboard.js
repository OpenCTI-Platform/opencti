import { compareValues, CyioError } from '../../utils.js';
import conf from '../../../../config/conf.js';
import {
  entitiesCountQuery,
  entitiesTimeSeriesQuery,
  entitiesDistributionQuery,
  dashboardSingularizeSchema as singularizeSchema,
} from './dashboard-sparqlQuery.js';
import { calculateRiskLevel } from '../../risk-assessments/riskUtils.js';
import { getReducer as getAssessmentReducer } from '../../risk-assessments/assessment-common/resolvers/sparql-query.js';

const cyioDashboardResolvers = {
  Query: {
    // Dashboard Workspace Wizard
    workspaceWizardConfig: async (_, args, { dbName, dataSources, selectMap }) => {
      const config = conf.get('workspaces:wizard:config');
      if (config === undefined || config.length === 0 || config === null) {
        throw new CyioError('Could not find workspace wizard configuration');
        // throw new UserInputError('Could not find workspace wizard configuration',{time_thrown: new Date()})
      }

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
            if (value instanceof Date) value = value.toISOString();
            if (value.trim().length === 0) {
              delete args[key];
              continue;
            }
          }
        }
      }
      // END WORKAROUND

      if (!('type' in args) && !('field' in args)) throw new CyioError(`Must specify either "type" or "field"`);
      if ('field' in args && !'match' in args) throw new CyioError(`"match" must be specified when using "field"`);
      if ('match' in args && !'field' in args) throw new CyioError(`"field" must specified when using "match"`);

      let response;
      const query = entitiesCountQuery(args);
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: query,
          queryId: `Select Entity count of ${args.field}`,
          singularizeSchema,
        });
      } catch (e) {
        console.error(e);
        throw e;
      }

      // none found
      if (response === undefined || response.length === 0) return null;
      return {
        total: response[0].total ? response[0].total : 0,
        count: response[0].count ? response[0].count : 0,
      };
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
            if (value instanceof Date) value = value.toISOString();
            if (value.trim().length === 0) {
              delete args[key];
              continue;
            }
          }
        }
      }
      // END WORKAROUND

      if (!('type' in args) && !('field' in args)) throw new CyioError(`Must specify either "type" or "field"`);
      if ('field' in args && !'match' in args) throw new CyioError(`"match" must be specified when using "field"`);
      if ('match' in args && !'field' in args) throw new CyioError(`"field" must specified when using "match"`);

      let response;
      const query = entitiesTimeSeriesQuery(args);
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: query,
          queryId: `Select Time Series of Entity`,
          singularizeSchema,
        });
      } catch (e) {
        console.error(e);
        throw e;
      }

      // none found
      if (response === undefined || response.length === 0) return null;
      if (Object.entries(response[0]).length === 0) return null;
      const bucket = {};

      // walk the array of responses
      for (const value of response) {
        const valueTimestamp = value.created;
        const year = valueTimestamp.getFullYear().toString();
        const dateValue = new Date(valueTimestamp.setUTCHours(0, 0, 0, 0));
        let label;
        switch (args.interval) {
          case 'day':
            label = `${valueTimestamp.toLocaleString('default', { month: 'short' })} ${valueTimestamp.getDate()}`;
            break;
          case 'week':
            const startDate = new Date(valueTimestamp.getFullYear(), 0, 1);
            const numberOfDays = Math.floor((valueTimestamp - startDate) / (24 * 60 * 60 * 1000));
            const weekNumber = Math.ceil((valueTimestamp.getDay() + 1 + numberOfDays) / 7);
            label = `Wk ${weekNumber} ${year}`;
            break;
          case 'month':
            label = `${valueTimestamp.toLocaleString('default', { month: 'short' })} ${year}`;
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
        } else bucket[label] = { date: dateValue, label, value: 1 };
      }

      const results = [];
      for (const key in bucket) {
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
            if (value instanceof Date) value = value.toISOString();
            if (value.trim().length === 0) {
              delete args[key];
              continue;
            }
          }
        }
      }
      // END WORKAROUND

      if (!('type' in args) && !('field' in args)) throw new CyioError('Must specified either type or field');
      if ('field' in args && !'match' in args) throw new CyioError(`"match" must be specified when using "field"`);
      if ('match' in args && !'field' in args) throw new CyioError(`"field" must specified when using "match"`);

      let response;
      const query = entitiesCountQuery(args);
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: query,
          queryId: `Select Entity count of ${args.field}`,
          singularizeSchema,
        });
      } catch (e) {
        console.error(e);
        throw e;
      }

      // none found
      if (response === undefined || response.length === 0) return null;
      return {
        total: response[0].total ? response[0].total : 0,
        count: response[0].count ? response[0].count : 0,
      };
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
            if (value instanceof Date) value = value.toISOString();
            if (value.trim().length === 0) {
              delete args[key];
              continue;
            }
          }
        }
      }
      // END WORKAROUND

      if (!('type' in args) && !('field' in args)) throw new CyioError(`Must specify either "type" or "field"`);
      if ('field' in args && !'match' in args) throw new CyioError(`"match" must be specified when using "field"`);
      if ('match' in args && !'field' in args) throw new CyioError(`"field" must specified when using "match"`);

      let response;
      const query = entitiesTimeSeriesQuery(args);
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: query,
          queryId: `Select Time Series of Entity`,
          singularizeSchema,
        });
      } catch (e) {
        console.error(e);
        throw e;
      }

      // none found
      if (response === undefined || response.length === 0) return null;
      if (Object.entries(response[0]).length === 0) return null;
      const bucket = {};

      // walk the array of responses
      for (const value of response) {
        const valueTimestamp = value.created;
        const year = valueTimestamp.getFullYear().toString();
        const dateValue = new Date(valueTimestamp.setUTCHours(0, 0, 0, 0));
        let label;
        switch (args.interval) {
          case 'day':
            label = `${valueTimestamp.toLocaleString('default', { month: 'short' })} ${valueTimestamp.getDate()}`;
            break;
          case 'week':
            const startDate = new Date(valueTimestamp.getFullYear(), 0, 1);
            const numberOfDays = Math.floor((valueTimestamp - startDate) / (24 * 60 * 60 * 1000));
            const weekNumber = Math.ceil((valueTimestamp.getDay() + 1 + numberOfDays) / 7);
            label = `Wk ${weekNumber} ${year}`;
            break;
          case 'month':
            label = `${valueTimestamp.toLocaleString('default', { month: 'short' })} ${year}`;
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
        } else bucket[label] = { date: dateValue, label, value: 1 };
      }

      const results = [];
      for (const key in bucket) {
        results.push(bucket[key]);
      }

      return results;
    },
    risksDistribution: async (_, args, { dbName, dataSources, selectMap }) => {
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
            if (value instanceof Date) value = value.toISOString();
            if (typeof value === 'number' && value === 0) {
              delete args[key];
              continue;
            }
            if (value instanceof String) {
              if (value.trim().length === 0) {
                delete args[key];
                continue;
              }
            }
          }
        }
      }
      // END WORKAROUND

      if (!('type' in args) && !('field' in args)) throw new CyioError(`Must specify either "type" or "field"`);
      if ('field' in args && !'match' in args) throw new CyioError(`"match" must be specified when using "field"`);
      if ('match' in args && !'field' in args) throw new CyioError(`"field" must specified when using "match"`);

      let response;
      const query = entitiesDistributionQuery(args);
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: query,
          queryId: `Select Distribution of Entity`,
          singularizeSchema,
        });
      } catch (e) {
        console.error(e);
        throw e;
      }

      // none found
      if (response === undefined || response.length === 0) return null;
      if (Object.entries(response[0]).length === 0) return null;

      for (const risk of response) {
        risk.risk_level = 'unknown';
        if (risk.cvssV2Base_score !== undefined || risk.cvssV3Base_score !== undefined) {
          // calculate the risk level
          const { riskLevel, riskScore } = calculateRiskLevel(risk);
          risk.risk_score = riskScore;
          risk.risk_level = riskLevel;
          if ('match' in args) risk.o = riskLevel;

          // clean up
          delete risk.cvssV2Base_score;
          delete risk.cvssV2Temporal_score;
          delete risk.cvssV3Base_score;
          delete risk.cvssV3Temporal_score;
          delete risk.available_exploit_values;
          delete risk.exploitability_ease_values;
        }
      }

      // sort the values
      let riskList;
      let sortBy;
      if (args.field === 'risk_level') {
        sortBy = 'risk_score';
        riskList = response.sort(compareValues(sortBy, 'desc'));
        response = riskList;
      }

      // build buckets for each of the potential match items
      const bucket = {};
      if ('match' in args) {
        for (const value of args.match) {
          bucket[value] = { label: value, value: 0 };
        }
        // for each response, increment the count in the match bucket
        for (const value of response) {
          if (value.o in bucket) {
            bucket[value.o].value++;
          } else {
            bucket[value.o] = { label: value.o, value: 1 };
          }
        }
      }
      if (!('match' in args)) {
        const reducer = getAssessmentReducer('RISK');
        let limit = 0;
        if ('limit' in args) {
          limit = args.limit;
        } else {
          limit = 5;
        }
        for (const value of response) {
          if (limit) {
            bucket[value.name] = {
              label: value.name,
              value: args.field === 'risk_level' ? value.risk_score : value.occurrences,
              entity: reducer(value),
            };
            limit--;
          }
        }
      }

      // convert the buckets into result format
      const results = [];
      for (const key in bucket) {
        results.push(bucket[key]);
      }

      return results;
    },
  },
  CyioObject: {
    __resolveType: (item) => {
      if (item.entity_type === 'risk') return 'Risk';
      if (item.entity_type === 'component') return 'Component';
      if (item.entity_type === 'inventory-item') return 'InventoryItem';
    },
  },
};

export default cyioDashboardResolvers;
