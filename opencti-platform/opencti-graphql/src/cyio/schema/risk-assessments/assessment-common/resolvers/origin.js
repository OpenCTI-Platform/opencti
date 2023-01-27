import { UserInputError } from 'apollo-server-express';
import { riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import { selectObjectIriByIdQuery } from '../../../global/global-utils.js';
import { compareValues, updateQuery, filterValues, CyioError } from '../../../utils.js';
import {
  getReducer,
  selectAllOrigins,
  deleteOriginQuery,
  insertOriginQuery,
  selectOriginQuery,
  attachToOriginQuery,
  detachFromOriginQuery,
  insertActorsQuery,
  deleteActorByIriQuery,
  selectActorByIriQuery,
  originPredicateMap,
} from './sparql-query.js';

const originResolvers = {
  Query: {
    origins: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllOrigins(selectMap.getNode('node'), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: 'Select Origin List',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer('ORIGIN');
        let filterCount;
        let resultCount;
        let limit;
        let offset;
        let limitSize;
        let offsetSize;
        limitSize = limit = args.first === undefined ? response.length : args.first;
        offsetSize = offset = args.offset === undefined ? 0 : args.offset;
        filterCount = 0;
        let originList;
        if (args.orderedBy !== undefined) {
          originList = response.sort(compareValues(args.orderedBy, args.orderMode));
        } else {
          originList = response;
        }

        if (offset > originList.length) return null;

        // for each Origin in the result set
        for (const origin of originList) {
          // skip down past the offset
          if (offset) {
            offset--;
            continue;
          }

          if (origin.id === undefined || origin.id == null) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${origin.iri} missing field 'id'; skipping`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(origin, args.filters, args.filterMode)) {
              continue;
            }
            filterCount++;
          }

          // if haven't reached limit to be returned
          if (limit) {
            const edge = {
              cursor: origin.iri,
              node: reducer(origin),
            };
            edges.push(edge);
            limit--;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0) return null;
        let hasNextPage = false;
        let hasPreviousPage = false;
        resultCount = originList.length;
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
    origin: async (_, { id }, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectOriginQuery(id, selectMap.getNode('origin'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select Origin',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer('ORIGIN');
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
    createOrigin: async (_, { input }, { dbName, selectMap, dataSources }) => {
      // Setup to handle embedded objects to be created
      let tasks;
      let actors;
      if (input.origin_actors !== undefined) {
        if (input.origin_actors.length === 0) throw new CyioError(`No origin of the Risk Response provided.`);
        actors = input.origin_actors;
      }

      if (input.related_tasks !== undefined && input.related_tasks !== null) {
        // attempt to convert task's id to IRI
        let sparqlQuery;
        let result;
        const taskIris = [];
        for (const taskId of input.related_tasks) {
          sparqlQuery = selectObjectIriByIdQuery(taskId, 'task');
          try {
            result = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Task',
              singularizeSchema,
            });
          } catch (e) {
            console.log(e);
            throw e;
          }
          if (result === undefined || result.length === 0)
            throw new CyioError(`Entity does not exist with ID ${taskId}`);
          taskIris.push(result[0].iri);
        }
        if (taskIris.length > 0) input.related_tasks = taskIris;
      }

      // create any Actors supplied and attach them to the Origin
      let sparqlQuery;
      let result;
      for (const actor of actors) {
        // check to see if the referenced actor exists and get its IRI
        sparqlQuery = selectObjectIriByIdQuery(actor.actor_ref, actor.actor_type);
        try {
          result = await dataSources.Stardog.queryById({
            dbName,
            sparqlQuery,
            queryId: 'Select Object',
            singularizeSchema,
          });
        } catch (e) {
          console.log(e);
          throw e;
        }
        if (result == undefined || result.length === 0)
          throw new CyioError(`Entity does not exist with ID ${actor.actor_ref}`);
        actor.actor_ref = result[0].iri;

        // if a role reference was provided
        if (actor.role_ref !== undefined) {
          // check if the role reference exists and get its IRI
          sparqlQuery = selectObjectIriByIdQuery(actor.role_ref, 'role');
          try {
            result = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Object',
              singularizeSchema,
            });
          } catch (e) {
            console.log(e);
            throw e;
          }
          if (result == undefined || result.length === 0)
            throw new CyioError(`Entity does not exist with ID ${actor.role_ref}`);
          actor.role_ref = result[0].iri;
        }
      }

      // create the Origin
      const { iri, id, query } = insertOriginQuery(input);
      try {
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: 'Create Origin',
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (actors.length > 0) {
        // create the Actors
        const { actorIris, query } = insertActorsQuery(actors);
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: query,
            queryId: 'Create Actor of Origin',
          });
        } catch (e) {
          console.log(e);
          throw e;
        }
        // attach Actor to the Origin
        const actorAttachQuery = attachToOriginQuery(id, 'origin_actors', actorIris);
        try {
          await dataSources.Stardog.create({
            dbName,
            queryId: 'Add Actor to Origin',
            sparqlQuery: actorAttachQuery,
          });
        } catch (e) {
          console.log(e);
          throw e;
        }
      }

      // retrieve information about the newly created Origin to return to the user
      const select = selectOriginQuery(id, selectMap.getNode('createOrigin'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: 'Select Origin',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      const reducer = getReducer('ORIGIN');
      return reducer(response[0]);
    },
    deleteOrigin: async (_, { id }, { dbName, dataSources }) => {
      // check that the Origin exists
      const sparqlQuery = selectOriginQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select Origin',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);
      const reducer = getReducer('ORIGIN');
      const origin = reducer(response[0]);

      // Delete any attached Actors
      if (origin.hasOwnProperty('origin_actors_iri')) {
        for (const actorIri of origin.origin_actors_iri) {
          const actorQuery = deleteActorByIriQuery(actorIri);
          try {
            await dataSources.Stardog.delete({
              dbName,
              sparqlQuery: actorQuery,
              queryId: 'Delete Actor from Origin',
            });
          } catch (e) {
            console.log(e);
            throw e;
          }
        }
      }

      // Detach any related tasks
      if (origin.hasOwnProperty('related_tasks_iri')) {
        const taskQuery = detachFromOriginQuery(id, 'related_tasks', origin.related_tasks_iri);
        try {
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: taskQuery,
            queryId: 'Delete Related Tasks from Origin',
          });
        } catch (e) {
          console.log(e);
          throw e;
        }
      }

      // Delete the Origin itself
      const query = deleteOriginQuery(id);
      try {
        await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: 'Delete Origin',
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      return id;
    },
    editOrigin: async (_, { id, input }, { dbName, dataSources, selectMap }) => {
      // make sure there is input data containing what is to be edited
      if (input === undefined || input.length === 0) throw new CyioError(`No input data was supplied`);

      // TODO: WORKAROUND to remove immutable fields
      input = input.filter(
        (element) => element.key !== 'id' && element.key !== 'created' && element.key !== 'modified'
      );

      // check that the object to be edited exists with the predicates - only get the minimum of data
      const editSelect = ['id'];
      for (const editItem of input) {
        editSelect.push(editItem.key);
      }

      const sparqlQuery = selectOriginQuery(id, editSelect);
      const response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: 'Select Origin',
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

      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/assessment/common#Origin-${id}`,
        'http://csrc.nist.gov/ns/oscal/assessment/common#Origin',
        input,
        originPredicateMap
      );
      if (query !== null) {
        let response;
        try {
          response = await dataSources.Stardog.edit({
            dbName,
            sparqlQuery: query,
            queryId: 'Update Origin',
          });
        } catch (e) {
          console.log(e);
          throw e;
        }

        if (response !== undefined && 'status' in response) {
          if (response.ok === false || response.status > 299) {
            // Handle reporting Stardog Error
            throw new UserInputError(response.statusText, {
              error_details: response.body.message ? response.body.message : response.body,
              error_code: response.body.code ? response.body.code : 'N/A',
            });
          }
        }
      }

      const select = selectOriginQuery(id, selectMap.getNode('editOrigin'));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: 'Select Origin',
        singularizeSchema,
      });
      const reducer = getReducer('ORIGIN');
      return reducer(result[0]);
    },
  },
  Origin: {
    origin_actors: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.origin_actors_iri === undefined) return [];
      const iriArray = parent.origin_actors_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer('ACTOR');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Actor')) {
            continue;
          }
          const sparqlQuery = selectActorByIriQuery(iri, selectMap.getNode('origin_actors'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Actor',
              singularizeSchema,
            });
          } catch (e) {
            console.log(e);
            throw e;
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            // TODO: fix the generation to use the assessment-platform  as the actor type value of Assessment Platforms
            if (
              response[0].actor_type !== undefined &&
              response[0].actor_type == 'tool' &&
              response[0].actor_ref !== undefined &&
              response[0].actor_ref.includes('AssessmentPlatform')
            ) {
              response[0].actor_type = 'assessment-platform';
            }
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
    related_tasks: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.related_tasks_iri === undefined) return [];
      const iriArray = parent.related_tasks_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer('TASK');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Task')) {
            continue;
          }
          const sparqlQuery = selectOscalTaskByIriQuery(iri, selectMap.getNode('related_tasks'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Task',
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

export default originResolvers;
