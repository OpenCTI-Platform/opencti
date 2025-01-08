import { registerGraphqlSchema } from '../../graphql/schema';
import disseminationListTypeDefs from './disseminationList.graphql';
import disseminationListResolvers from './disseminationList-resolver';

registerGraphqlSchema({
  schema: disseminationListTypeDefs,
  resolver: disseminationListResolvers,
});
