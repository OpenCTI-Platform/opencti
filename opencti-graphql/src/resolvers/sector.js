import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addSector,
  sectorDelete,
  findAll,
  findById,
  markingDefinitions,
  sectorEditContext,
  sectorEditField,
  sectorAddRelation,
  sectorDeleteRelation,
  sectorCleanContext
} from '../domain/sector';
import { fetchEditContext, pubsub } from '../database/redis';
import { auth, withCancel } from './wrapper';

const sectorResolvers = {
  Query: {
    sector: auth((_, { id }) => findById(id)),
    sectors: auth((_, args) => findAll(args))
  },
  Sector: {
    markingDefinitions: (sector, args) =>
      markingDefinitions(sector.id, args),
    editContext: auth(sector => fetchEditContext(sector.id))
  },
  Mutation: {
    sectorEdit: auth((_, { id }, { user }) => ({
      delete: () => sectorDelete(id),
      fieldPatch: ({ input }) => sectorEditField(user, id, input),
      contextPatch: ({ input }) => sectorEditContext(user, id, input),
      relationAdd: ({ input }) => sectorAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        sectorDeleteRelation(user, id, relationId)
    })),
    sectorAdd: auth((_, { input }, { user }) => addSector(user, input))
  },
  Subscription: {
    sector: {
      resolve: payload => payload.instance,
      subscribe: auth((_, { id }, { user }) => {
        sectorEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.Sector.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          sectorCleanContext(user, id);
        });
      })
    }
  }
};

export default sectorResolvers;
