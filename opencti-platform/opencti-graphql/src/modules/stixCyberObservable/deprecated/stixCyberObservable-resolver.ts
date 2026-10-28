import type { Resolvers } from '../../../generated/graphql';
import { promoteObservableToIndicator } from './stixCyberObservable-domain';

import stixCyberObservableResolvers from '../../../resolvers/stixCyberObservable';

const stixCyberObservableResolvers_deprecated: Resolvers = {
  Mutation: {
    stixCyberObservableEdit: (_, { id }, context) => {
      const baseResolvers = stixCyberObservableResolvers.Mutation.stixCyberObservableEdit(_, { id }, context);
      return {
        ...baseResolvers,
        // region [>=6.2 & <6.8]
        promote: () => promoteObservableToIndicator(context, context.user, id),
        // endregion
      } as any;
    },
  },
};

export default stixCyberObservableResolvers_deprecated;
