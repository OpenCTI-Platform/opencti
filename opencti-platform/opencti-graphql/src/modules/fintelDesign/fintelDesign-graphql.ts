import { registerGraphqlSchema } from '../../graphql/schema';
import fintelDesignResolvers from './fintelDesign-resolver';
import designTypeDefs from './fintelDesign.graphql';

registerGraphqlSchema({
  schema: designTypeDefs,
  resolver: fintelDesignResolvers,
});
