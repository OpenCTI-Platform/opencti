import { registerGraphqlSchema } from '../../graphql/schema';
import fintelDesignResolvers from './fintelDesign-resolver';
import fintelDesignTypeDefs from './fintelDesign.graphql';

registerGraphqlSchema({
  schema: fintelDesignTypeDefs,
  resolver: fintelDesignResolvers,
});
