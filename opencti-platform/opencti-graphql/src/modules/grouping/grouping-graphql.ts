import { registerGraphqlSchema } from '../../graphql/schema';
import groupingTypeDefs from './grouping.graphql';
import groupingResolvers from './grouping-resolver';

registerGraphqlSchema({
  schema: groupingTypeDefs,
  resolver: groupingResolvers,
});
