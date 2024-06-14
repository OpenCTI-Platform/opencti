import { promoteObservableToIndicator } from './stixCyberObservable-domain';

import stixCyberObservableResolvers from '../../../resolvers/stixCyberObservable';

const stixCyberObservableResolvers_deprecated = {
  Mutation: {
    stixCyberObservableEdit: (_, { id }, context) => {
      const baseResolvers = stixCyberObservableResolvers.Mutation.stixCyberObservableEdit(_, { id }, context);
      return {
        ...baseResolvers,
        // region [>=6.2 & <6.5]
        promote: () => promoteObservableToIndicator(context, context.user, id),
        // endregion
      };
    },
  },
};

export default stixCyberObservableResolvers_deprecated;
