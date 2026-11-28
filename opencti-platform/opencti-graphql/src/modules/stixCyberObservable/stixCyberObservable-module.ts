import type { ModuleDescriptor } from '../module-descriptor';
import type { Resolvers } from '../../generated/graphql';
import stixCyberObservableResolvers_deprecated from './deprecated/stixCyberObservable-resolver';
import stixCyberObservableTypeDefs from './deprecated/stixCyberObservable.graphql';

// SCO are not implemented as module yet ; only the deprecated part of the module is implemented
const stixCyberObservableModule: ModuleDescriptor = {
  id: 'stixCyberObservable',
  // TODO the edit mutations resolve to functions where the generated graphql types expect values,
  // which the untyped registerGraphqlSchema never checked.
  graphqlSchemas: [{ schema: stixCyberObservableTypeDefs, resolver: stixCyberObservableResolvers_deprecated as unknown as Resolvers }],
};

export default stixCyberObservableModule;
