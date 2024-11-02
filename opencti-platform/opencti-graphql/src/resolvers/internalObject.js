import { internalObjectCleanContext, internalObjectEditContext } from '../domain/internalObject';
import { BUS_TOPICS } from '../config/conf';
import { subscribeToInstanceEvents } from '../graphql/subscriptionWrapper';
import { ABSTRACT_INTERNAL_OBJECT } from '../schema/general';

const internalObjectResolvers = {
  InternalObject: {
    // eslint-disable-next-line
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-|_)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      /* v8 ignore next */
      return 'Unknown';
    },
  },
  Subscription: {
    internalObject: {
      resolve: /* v8 ignore next */ (payload) => payload.instance,
      subscribe: /* v8 ignore next */ (_, { id }, context) => {
        const preFn = () => internalObjectEditContext(context, context.user, id);
        const cleanFn = () => internalObjectCleanContext(context, context.user, id);
        const bus = BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT];
        return subscribeToInstanceEvents(_, context, id, [bus.EDIT_TOPIC], { type: ABSTRACT_INTERNAL_OBJECT, preFn, cleanFn });
      },
    },
  },
};

export default internalObjectResolvers;
