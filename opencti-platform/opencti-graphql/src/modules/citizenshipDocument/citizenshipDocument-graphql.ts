import { registerGraphqlSchema } from '../../graphql/schema';
import citizenshipDocumentResolvers from './citizenshipDocument-resolver';
import citizenshipDocumentTypeDefs from './citizenshipDocument.graphql';

registerGraphqlSchema({
  schema: citizenshipDocumentTypeDefs,
  resolver: citizenshipDocumentResolvers,
});
