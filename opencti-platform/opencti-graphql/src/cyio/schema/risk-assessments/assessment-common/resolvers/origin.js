import {riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import {objectMap, selectObjectIriByIdQuery} from '../../../global/global-utils.js';
import {compareValues, updateQuery, filterValues} from '../../../utils.js';
import {UserInputError} from "apollo-server-express";
import {
  getReducer, 
  selectAllOrigins,
  deleteOriginQuery,
  insertOriginQuery,
  selectOriginQuery,
  selectOriginByIriQuery,
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
      const sparqlQuery = selectAllOrigins(selectMap.getNode("node"), args.filters);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Origin List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer("ORIGIN");
        let limit = (args.first === undefined ? response.length : args.first) ;
        let offset = (args.offset === undefined ? 0 : args.offset) ;
        let originList ;
        if (args.orderedBy !== undefined ) {
          originList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          originList = response;
        }

        if (offset > originList.length) return null;

        // for each Origin in the result set
        for (let origin of originList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (origin.id === undefined || origin.id == null ) {
            console.log(`[DATA-ERROR] object ${origin.iri} is missing required properties; skipping object.`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(origin, args.filters, args.filterMode) ) {
              continue
            }
          }

          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: origin.iri,
              node: reducer(origin),
            }
            edges.push(edge)
            limit--;
          }
        }
        if (edges.length === 0 ) return null;
        return {
          pageInfo: {
            startCursor: edges[0].cursor,
            endCursor: edges[edges.length-1].cursor,
            hasNextPage: (args.first > originList.length),
            hasPreviousPage: (args.offset > 0),
            globalCount: originList.length,
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
    origin: async (_, {id}, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectOriginQuery(id, selectMap.getNode("origin"));
      let response;
      try {
          response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Origin",
          singularizeSchema
          });
      } catch (e) {
          console.log(e)
          throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
          const reducer = getReducer("ORIGIN");
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
    },
  },
  Mutation: {
    createOrigin: async ( _, {input}, {dbName, selectMap, dataSources} ) => {
      // Setup to handle embedded objects to be created
      let tasks, actors;
      if (input.origin_actors !== undefined) actors = input.origin_actors;

      if (input.related_tasks !== undefined && input.related_tasks !== null) {
				// attempt to convert task's id to IRI
				let sparqlQuery, result;
				let taskIris = [];
				for (let taskId of input.related_tasks) {
					sparqlQuery = selectObjectIriByIdQuery( taskId, 'task' );
					try {
						result = await dataSources.Stardog.queryById({
						dbName,
						sparqlQuery,
						queryId: "Select Task",
						singularizeSchema
						});
					} catch (e) {
							console.log(e)
							throw e
					}
					if (result === undefined || result.length === 0) throw new UserInputError(`Entity does not exist with ID ${taskId}`);
					taskIris.push(result[0].iri)
				}
				if (taskIris.length > 0) input.related_tasks = taskIris;
			}

      // create the Origin
      const {iri, id, query} = insertOriginQuery(input);
      try {
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: "Create Origin"
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      // create any Actors supplied and attach them to the Origin
      if (actors !== undefined && actors !== null ) {
        // create the Origin
        const { actorIris, query } = insertActorsQuery( actors );
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: query,
            queryId: "Create Actor of Origin"
          });
        } catch (e) {
          console.log(e)
          throw e
        }

        // attach Actor to the Origin
        const actorAttachQuery = attachToOriginQuery(id, 'origin_actors', actorIris );
        try {
          await dataSources.Stardog.create({
            dbName,
            queryId: "Add Actor to Origin",
            sparqlQuery: actorAttachQuery
          });
        } catch (e) {
          console.log(e)
          throw e
        }
      }

      // retrieve information about the newly created Origin to return to the user
      const select = selectOriginQuery(id, selectMap.getNode("createOrigin"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: "Select Origin",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      const reducer = getReducer("ORIGIN");
      return reducer(response[0]);
    },
    deleteOrigin: async ( _, {id}, {dbName, dataSources} ) => {
      // check that the Origin exists
      const sparqlQuery = selectOriginQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Origin",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      let reducer = getReducer("ORIGIN");
      const origin = (reducer(response[0]));

      // Delete any attached Actors
      if (origin.hasOwnProperty('origin_actors_iri')) {
        for (const actorIri of origin.origin_actors_iri) {
          const actorQuery = deleteActorByIriQuery(actorIri);
          try {
            await dataSources.Stardog.delete({
              dbName,
              sparqlQuery: actorQuery,
              queryId: "Delete Actor from Origin"
            });
          } catch (e) {
            console.log(e)
            throw e
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
            queryId: "Delete Related Tasks from Origin"
          });
        } catch (e) {
          console.log(e)
          throw e
        }    
      }

      // Delete the Origin itself
      const query = deleteOriginQuery(id);
      try {
        await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: "Delete Origin"
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      return id;
    },
    editOrigin: async (_, {id, input}, {dbName, dataSources, selectMap}) => {
      // check that the Origin exists
      const sparqlQuery = selectOriginQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Origin",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/assessment/common#Origin-${id}`,
        "http://csrc.nist.gov/ns/oscal/assessment/common#Origin",
        input,
        originPredicateMap
      )
      await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update Origin"
      });
      const select = selectOriginQuery(id, selectMap.getNode("editOrigin"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select Origin",
        singularizeSchema
      });
      const reducer = getReducer("ORIGIN");
      return reducer(result[0]);
    },

  },
  Origin: {
		origin_actors: async (parent, args, {dbName, dataSources, selectMap}) => {
      if (parent.origin_actors_iri === undefined) return [];
      let iriArray = parent.origin_actors_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer("ACTOR");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Actor')) {
            continue;
          }
          const sparqlQuery = selectActorByIriQuery(iri, selectMap.getNode('origin_actors'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Actor",
              singularizeSchema
            });
          } catch (e) {
            console.log(e)
            throw e
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            // TODO: fix the generation to use the assessment-platform  as the actor type value of Assessment Platforms
            if ((response[0].actor_type !== undefined && response[0].actor_type == 'tool') && 
                (response[0].actor_ref !== undefined && response[0].actor_ref.includes('AssessmentPlatform'))) {
                  response[0].actor_type = 'assessment-platform';
                }
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
    related_tasks: async (parent, args, {dbName, dataSources, selectMap}) => {
      if (parent.related_tasks_iri === undefined) return [];
      let iriArray = parent.related_tasks_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer("TASK");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Task')) {
            continue;
          }
          const sparqlQuery = selectOscalTaskByIriQuery(iri, selectMap.getNode("related_tasks"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Task",
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
  }
}

export default originResolvers;