import { registerGraphqlSchema } from '../../../graphql/schema';
import stixCyberObservableResolvers_deprecated from './stixCyberObservable-resolver';
import stixCyberObservableTypeDefs from './stixCyberObservable.graphql';

registerGraphqlSchema({
  schema: stixCyberObservableTypeDefs,
  resolver: stixCyberObservableResolvers_deprecated,
});
