import { registerGraphqlSchema } from '../../graphql/schema';
import provenanceTypeDefs from './provenance.graphql';
import provenanceResolvers from './provenance-resolvers';

registerGraphqlSchema({
  schema: provenanceTypeDefs,
  resolver: provenanceResolvers,
});
