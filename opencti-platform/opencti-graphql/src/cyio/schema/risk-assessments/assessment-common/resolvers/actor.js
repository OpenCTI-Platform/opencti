import { UserInputError } from 'apollo-server-express';
import { riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import { compareValues, updateQuery, filterValues, CyioError } from '../../../utils.js';
import { objectMap, selectObjectIriByIdQuery, selectObjectByIriQuery } from '../../../global/global-utils.js';
import {
  selectExternalReferenceByIriQuery,
  getReducer as getGlobalReducer,
} from '../../../global/resolvers/sparql-query.js';
import {
  getReducer as getCommonReducer,
  // selectObjectByIriQuery,
} from '../../oscal-common/resolvers/sparql-query.js';
import {
  getReducer,
  insertActorQuery,
  selectActorQuery,
  selectAllActors,
  deleteActorQuery,
  actorPredicateMap,
} from './sparql-query.js';

const actorResolvers = {
  Query: {
    actors: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllActors(selectMap.getNode('node'), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: 'Select Actors List',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer('ACTOR');
        let filterCount;
        let resultCount;
        let limit;
        let offset;
        let limitSize;
        let offsetSize;
        limitSize = limit = args.first === undefined ? response.length : args.first;
        offsetSize = offset = args.offset === undefined ? 0 : args.offset;
        filterCount = 0;
        let actorList;
        if (args.orderedBy !== undefined) {
          actorList = response.sort(compareValues(args.orderedBy, args.orderMode));
        } else {
          actorList = response;
        }

        if (offset > actorList.length) return null;

        // for each Actor in the result set
        for (const actor of actorList) {
          // skip down past the offset
          if (offset) {
            offset--;
            continue;
          }

          if (actor.id === undefined || actor.id == null) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${actor.iri} missing field 'id'; skipping`);
            continue;
          }
          if (actor.actor_ref === undefined || actor.actor_ref == null) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${actor.iri} missing field 'actor_ref'; skipping`);
          }

          // TODO: fix the generation to use the assessment-platform as the actor type value of Assessment Platforms
          if (actor.actor_type == 'tool' && actor.actor_ref.includes('AssessmentPlatform')) {
            console.log(
              `[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${actor.iri} conflicting fields 'actor_type' and 'actor_ref'; see ADO #4853`
            );
            response[0].actor_type = 'assessment-platform';
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(actor, args.filters, args.filterMode)) {
              continue;
            }
            filterCount++;
          }

          // if haven't reached limit to be returned
          if (limit) {
            const edge = {
              cursor: actor.iri,
              node: reducer(actor),
            };
            edges.push(edge);
            limit--;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0) return null;
        let hasNextPage = false;
        let hasPreviousPage = false;
        resultCount = actorList.length;
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
    actor: async (_, { id }, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectActorQuery(id, selectMap.getNode('actor'));
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

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer('ACTOR');
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
    createActor: async (_, { input }, { dbName, selectMap, dataSources }) => {
      // Setup to handle embedded objects to be created
      if (input.actor_ref !== undefined) {
        // convert actor id to IRI
        const sparqlQuery = selectObjectIriByIdQuery(input.actor_ref, input.actor_type);
        let result;
        try {
          result = await dataSources.Stardog.queryById({
            dbName,
            sparqlQuery,
            queryId: 'Select Actor',
            singularizeSchema,
          });
        } catch (e) {
          console.log(e);
          throw e;
        }
        if (result === undefined || result.length === 0)
          throw new CyioError(`Entity does not exist with ID ${input.actor_ref}`);
        input.actor_ref = result[0].iri;
      }

      if (input.role_ref !== undefined) {
        // convert actor id to IRI
        const sparqlQuery = selectObjectIriByIdQuery(input.role_ref, 'role');
        let result;
        try {
          result = await dataSources.Stardog.queryById({
            dbName,
            sparqlQuery,
            queryId: 'Select Role',
            singularizeSchema,
          });
        } catch (e) {
          console.log(e);
          throw e;
        }
        if (result === undefined || result.length === 0)
          throw new CyioError(`Entity does not exist with ID ${input.role_ref}`);
        input.role_ref = result[0].iri;
      }

      // create the Actor
      const { id, query } = insertActorQuery(input);
      try {
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: 'Create Actor',
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      // add the Actor to the supplied parent

      // retrieve information about the newly created Actor to return to the user
      const select = selectActorQuery(id, selectMap.getNode('createActor'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: 'Select Actor',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      const reducer = getReducer('ACTOR');
      return reducer(response[0]);
    },
    deleteActor: async (_, { id }, { dbName, dataSources }) => {
      // check that the Actor exists
      const sparqlQuery = selectActorQuery(id, null);
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

      if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);
      const reducer = getReducer('ACTOR');
      const actor = reducer(response[0]);

      // Detach any associated tool, assessment platform, or party
      if (actor.hasOwnProperty('actor_ref_iri')) {
        const actorIri = actor.actor_ref_iri;
        const actorQuery = detachFromActorQuery(id, 'actor', actorIri);
        try {
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: actorQuery,
            queryId: 'Detaching Actor target from Actor',
          });
        } catch (e) {
          console.log(e);
          throw e;
        }
      }
      // Detach any associated role
      if (actor.hasOwnProperty('role_ref_iri')) {
        const roleIri = actor.role_ref_iri;
        const roleQuery = detachFromActorQuery(id, 'role', roleIri);
        try {
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: roleQuery,
            queryId: 'Detaching Role target from Actor',
          });
        } catch (e) {
          console.log(e);
          throw e;
        }
      }

      // delete the Actor
      const query = deleteActorQuery(id);
      await dataSources.Stardog.delete({
        dbName,
        sparqlQuery: query,
        queryId: 'Delete Actor',
      });
      return id;
    },
    editActor: async (_, { id, input }, { dbName, dataSources, selectMap }) => {
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

      const sparqlQuery = selectActorQuery(id, editSelect);
      const response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: 'Select Actor',
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
        `http://csrc.nist.gov/ns/oscal/assessment/common#Actor-${id}`,
        'http://csrc.nist.gov/ns/oscal/assessment/common#Actor',
        input,
        actorPredicateMap
      );
      if (query !== null) {
        let response;
        try {
          response = await dataSources.Stardog.edit({
            dbName,
            sparqlQuery: query,
            queryId: 'Update OSCAL Actor',
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

      const select = selectActorQuery(id, selectMap.getNode('editActor'));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: 'Select Actor',
        singularizeSchema,
      });
      const reducer = getReducer('ACTOR');
      return reducer(result[0]);
    },
  },
  // field-level resolvers
  Actor: {
    links: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.links_iri === undefined) return [];
      const iriArray = parent.links_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer('EXTERNAL-REFERENCE');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('ExternalReference')) {
            continue;
          }
          const sparqlQuery = selectExternalReferenceByIriQuery(iri, selectMap.getNode('links'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Link',
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
    actor_ref: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.actor_ref_iri === undefined) return null;
      // TODO: WORKAROUND to fix the generation to use the assessment-platform as the actor type value of Assessment Platforms
      if (parent.actor_type == 'tool' && parent.actor_ref_iri.includes('AssessmentPlatform'))
        parent.actor_type = 'assessment-platform';
      const iri = parent.actor_ref_iri;
      const reducer = getReducer(parent.actor_type.toUpperCase());
      const sparqlQuery = selectObjectByIriQuery(iri, parent.actor_type, selectMap.getNode('actor_ref'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select Object',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      if (response === undefined) return [];
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
    role_ref: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.role_ref_iri === undefined) return null;
      const iri = parent.role_ref_iri;
      const reducer = getCommonReducer('ROLE');
      const sparqlQuery = selectObjectByIriQuery(iri, 'role', selectMap.getNode('role_ref'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select Object',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      if (response === undefined) return [];
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
    __resolveType: (item) => {
      return objectMap[item.entity_type].graphQLType;
    },
  },
  ActorTarget: {
    __resolveType: (item) => {
      return objectMap[item.entity_type].graphQLType;
    },
  },
};

export default actorResolvers;
