import type { ModuleDescriptor } from '../module-descriptor';
import stixCyberObservableResolvers_deprecated from './deprecated/stixCyberObservable-resolver';
import stixCyberObservableTypeDefs from './deprecated/stixCyberObservable.graphql';

// SCO are not implemented as module yet ; only the deprecated part of the module is implemented
const stixCyberObservableModule: ModuleDescriptor = {
  id: 'stixCyberObservable',
  graphqlSchemas: [{ schema: stixCyberObservableTypeDefs, resolver: stixCyberObservableResolvers_deprecated }],
};

export default stixCyberObservableModule;
