import { withFilter } from 'graphql-subscriptions';
import { internalObjectCleanContext, internalObjectEditContext } from '../domain/internalObject';
import { BUS_TOPICS } from '../config/conf';
import { pubSubAsyncIterator } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { ABSTRACT_INTERNAL_OBJECT } from '../schema/general';

const internalObjectResolvers = {
  InternalObject: {
    // eslint-disable-next-line
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-|_)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      /* istanbul ignore next */
      return 'Unknown';
    },
  },
  Subscription: {
    internalObject: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, context) => {
        internalObjectEditContext(context, context.user, id);
        const bus = BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT];
        const filtering = withFilter(
          () => pubSubAsyncIterator([bus.EDIT_TOPIC, bus.CONTEXT_TOPIC]),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== context.user.id && payload.instance.id === id;
          }
        )(_, { id }, context);
        return withCancel(filtering, () => {
          internalObjectCleanContext(context, context.user, id);
        });
      },
    },
  },
};

export default internalObjectResolvers;
