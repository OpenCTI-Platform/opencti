import type { Resolvers, ResolversTypes } from '../../../generated/graphql';
import { promoteObservableToIndicator } from './stixCyberObservable-domain';

import stixCyberObservableResolvers from '../../../resolvers/stixCyberObservable';

const stixCyberObservableResolvers_deprecated: Resolvers = {
  Mutation: {
    stixCyberObservableEdit: (_, { id }, context) => {
      const baseResolvers = stixCyberObservableResolvers.Mutation.stixCyberObservableEdit(_, { id }, context);
      // TODO the edit mutations come from the untyped resolvers of stixCyberObservable.js, whose arguments are
      // inferred from the javascript, not from the schema: editMutations can check them once they are typed.
      return {
        ...baseResolvers,
        // region [>=6.2 & <6.8]
        promote: () => promoteObservableToIndicator(context, context.user, id),
        // endregion
      } as unknown as ResolversTypes['StixCyberObservableEditMutations'];
    },
  },
};

export default stixCyberObservableResolvers_deprecated;
